# DCA chain-key profile: construction and delegation

Status: Public Working Draft

## Abstract

This section is informative.

This specification defines derivable authority over one period-key family:
`chainKey[t]` derives the period key for `t` and earlier positions inside
one independently rooted chain window. The period key itself, `periodKey[t]`,
keeps the meaning the base profile gives it.

A publisher that uses the chain-key profile's canonical construction for
a family generation creates a chain-bearing family generation and derives its
canonical period keys.
It may delegate selected period keys to restrict an issuer to specific
coordinates, or delegate a positioned chain key to give the issuer a compact
ceiling over many coordinates. A chain-capable issuer may return period keys to
a period-key-only client or return a compact chain position when the complete
range from the window start through that position is authorized and the route's
trusted configuration establishes that its clients accept it in the selected
transport mode. A period-capability route that does not select chain supply
carries period keys only.

<a id="scope-and-status"></a>
## 1. Introduction

This document defines the optional chain-key profile
`dca-profile-chain-keys`. The profile depends on `dca-profile-period-keys` and fixes
one canonical construction that derives period keys (`periodKey`) from
positioned chain keys. It also defines the construction's window geometry,
coordinate labels, carrier, envelope binding, response member, bounds and role
requirements. Construction and delegation stay together here.

[spec-profile--period-keys.md](spec-profile--period-keys.md) defines the `periodKey[t]`
capability that this construction produces and the base period-key
requirements every role meets before a selected chain-key duty can operate.
This document
imports that period-key meaning and adds no second definition of it. A
period-key-only issuer or client does not need this document; a publisher
privately using the canonical construction does.

The construction transcript changes only under a new construction identifier
(Section 6); the protocol maxima are fixed in Section 22. A conformance claim
that includes a chain-key duty waits on published conformance evidence.

The model:

- `periodKey` is the base capability of the period-key profile and the
  interoperability floor for every role that implements it;
- a publisher may build a family generation with the canonical construction
  (Section 6), so period-key-only and chain-capable issuers open the same
  article wraps;
- derivable `chainKey` is the profile's capability; and
- issuer chain input, issuer chain output, client relay and client derivation
  are four separately selectable capabilities. A capability the profile
  defines is not a capability every actor implements.

[spec--data-format.md](spec--data-format.md) defines the JSON, identifier and
binary-string rules the members of Section 12 use; Section 12.1 defines their
placement and structural admission.
[guide--chain-keys.md](guide--chain-keys.md) is the readable companion.
[spec--security-model.md](spec--security-model.md) is the mandatory security
boundary.

### 1.1. Requirements language

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

### 1.2. Profile selection and dependencies

This optional profile depends on `dca-profile-period-keys`. Its rules apply
only when it is additionally selected. The profile relationship is:

```text
dca-profile-baseline
└── dca-profile-period-keys
    └── dca-profile-chain-keys
```

This document defines the canonical construction, the supply forms
(Section 11), the role requirements of publisher, request path, issuer and
client (Section 9), and the issuer decision (Section 13).
Supply forms are not separate profiles.

Trusted publisher and deployment configuration selects this profile before a
render is produced
(Section 10);
DCA v1 defines no runtime capability advertisement.

<a id="design-goals"></a>
## 2. Design goals

This section is informative.
[guide--chain-keys.md](guide--chain-keys.md) explains the design goals.

<a id="non-goals"></a>
## 3. Non-goals

This document does not define range trees, group-derivation trees or
multi-recipient public-key envelopes.

<a id="actors-and-trust"></a>
## 4. Actors and trust

This section is informative. The actors are those of
[spec-profile--period-keys.md](spec-profile--period-keys.md); Section 9 states each role's
chain-key duties.

<a id="key-and-capability-model"></a>
## 5. Key and capability model

A period key `periodKey[t]` has the meaning
[spec-profile--period-keys.md](spec-profile--period-keys.md#periodkeyt) gives it. This section
adds the generation facts the profile fixes, the derivable form and its reach.

<a id="generation-and-window-identity"></a>
### 5.1. Generation and window identity

A family generation that uses the canonical construction fixed by
`dca-profile-chain-keys` additionally fixes,
beyond the base facts in
[spec-profile--period-keys.md](spec-profile--period-keys.md#period-key-family-generation-and-window-identity):

- the publisher's derivation secret (`keyDerivationSecret`);
- the chain-key profile and its canonical construction; and
- its resolved period/window geometry.

Replacing the derivation secret starts new dependent family generations, even
when profile and geometry stay the same. Changing the chain-key profile or a
geometry value also starts a new family generation. The recipient and cache
retain which construction interprets each capability (Section 19).

A window is a deterministic subdivision *within* one family generation, not a
new family or generation.

<a id="chainkeyt"></a>
### 5.2. `chainKey[t]`

`chainKey[t]` is a positioned, derivation-capable **chain key** within one
independently rooted window. It is not the `periodKey[t]` that opens an item
wrap: a period key derives no chain key or other period key. A holder can
derive period keys from the window start through `t`. The chain key produces:

- the canonical period key `periodKey[t]`; and
- preceding chain positions and their canonical period keys down to the
  beginning of that window.

It cannot derive a later position or cross into another independently rooted
window.

The same positioned chain key may occupy two operational roles:

- a **supplied ceiling** is the chain key the publisher gives an issuer; it is
  normally the root chain key, but a lower supplied position is valid; and
- a **cutoff** is the positioned capability returned by an issuer to a client,
  deriving from that cutoff back to the window start.

The **root chain key** is `C[N-1]`, the first chain key derived for a window.
The publisher creates it at the window's last period, then derives earlier
chain keys backward from it. There is no separate root key above it. Root and
cutoff are positions or uses of the same key kind, not separate wire key types;
there is no wire `root` or `anchor` key type.

<a id="capability-reach"></a>
### 5.3. Capability reach

```text
item contentKey
    opens one content item in one render

periodKey[t]
    opens all matching wraps at one (family generation, t)

chainKey[t]
    derives period keys that open matching wraps from the start of its
    independently rooted window through t
```

Metadata cannot narrow the cryptographic reach of a raw chain key. If a client
receives `chainKey[t]`, policy must authorize everything its bytes can
derive under the selected profile.

<a id="canonical-construction"></a>
## 6. Canonical construction

This section defines the one canonical construction fixed by
`dca-profile-chain-keys`. Its chain key and period key are each exactly 16
octets, and its publisher-retained `keyDerivationSecret` remains 32 octets. It
produces the period keys of
`dca-profile-period-keys` in [spec--profiles.md](spec--profiles.md).

The publisher selects this construction for a family generation in trusted
route configuration (Section 10). Its identifier is
`dca-construction-chain-keys`, distinct from the profile identifier
`dca-profile-chain-keys`; it is not a wire member and has no alias. Any
incompatible change to the transcript, the KDF, the geometry parameter rules,
the context encoding or the label grammar of Section 7.3 requires a new
construction identifier and gives new
derived values; an unchanged construction keeps its identifier across DCA
releases and profile renames, and an editorial clarification does not change
it.

<a id="model"></a>
### 6.1. Model

```text
C[N-1]  = Root(keyDerivationSecret, family, geometry, windowStart)
C[i]    = Step(C[i+1], family, geometry, windowStart, i)     0 ≤ i < N-1
P[i]    = Leaf(C[i],   family, geometry, windowStart, i)     0 ≤ i < N
periodKey[t] = P[position(t)]
```

`C[i]` is the chain key at position `i`; `C[N-1]` is the root chain key.
`P[i]` is the period key at position `i`. No role uses a chain key directly as
an AES wrapping key.

<a id="inputs"></a>
### 6.2. Inputs

| Input | Form |
| --- | --- |
| `keyDerivationSecret` | exactly 32 octets, generated or provisioned with full-strength randomness within one publisher site/security namespace |
| `accessGroup` | an [`identifier`](spec--data-format.md#21-identifiers) |
| `chainsPerDay`, `periodMinutes` | the resolved pair from [Windows](#windows) |
| `windowStart` | minutes since 1970-01-01T00:00Z of the window start |
| `position` | `0 ≤ i < N` |

A logical family is the period-key family of period-keys Section 5.1.

A derivation secret (`keyDerivationSecret`) is one publisher-scoped, retained
32-octet input with a publisher-managed retention, replacement, and deletion
lifecycle. One derivation secret MAY serve several access-group family
generations inside the same mutually trusted publisher site/security namespace
because the identified Root context binds
`accessGroup`, construction and geometry. It MUST NOT be reused across sites
or publisher security namespaces. It never crosses the publisher trust
boundary and is never a delivered, encryption, MAC, signing or envelope key.
A key service that starts from a wider master secret derives each
publisher-scoped `keyDerivationSecret` independently before this construction
profile; the tenant or namespace used for that derivation is key-service
configuration, never a wire coordinate. Issuer identity, publisher context origin,
publisher signing-key identity and render identity do not enter any context.

The only purposes selected here are Root, Step and Leaf: Root consumes this
secret, while Step and Leaf consume a chain key under their distinct contexts.
No standalone base period-key derivation is selected.

<a id="primitive"></a>
### 6.3. Primitive

Every derivation is one HKDF-SHA-256 invocation (RFC 5869) with an empty salt.
Root and Step each produce a chain key of exactly 16 octets. Leaf produces the
16-octet period key that
[spec-profile--period-keys.md](spec-profile--period-keys.md#base-period-key-requirements)
defines. The two output widths coincide:

```text
HKDF(ikm, info, width) = HKDF-Expand(HKDF-Extract(salt = "", ikm), info, width)
```

<a id="context-encoding"></a>
### 6.4. Context encoding

Contexts are binary. Integers are unsigned big-endian of fixed width. Strings
are length-prefixed by their encoded byte length. No delimiter, no JSON, no
text form is authoritative.

```text
u8   domain          0x01 root, 0x02 step, 0x03 leaf
str  constructionId  u16 length || UTF-8 "dca-construction-chain-keys"
str  accessGroup     u16 length || UTF-8 octets
u16  chainsPerDay
u16  periodMinutes
u32  windowStart     minutes since 1970-01-01T00:00Z (Section 7.3)
u16  position        N - 1 in the root context; the derived position
                     in step and leaf

ROOT_INFO(family, geometry, w)    = 0x01 || constructionId || accessGroup
                                    || chainsPerDay || periodMinutes || w
                                    || (N - 1)
STEP_INFO(family, geometry, w, i) = 0x02 || constructionId || accessGroup
                                    || chainsPerDay || periodMinutes || w || i
LEAF_INFO(family, geometry, w, i) = 0x03 || constructionId || accessGroup
                                    || chainsPerDay || periodMinutes || w || i
```

Each symbol in the three expressions is encoded as its row in the table
above, so `constructionId` and `accessGroup` carry their `u16` length prefix; the
domain octet is the literal shown and `(N - 1)` in `ROOT_INFO` uses the `u16`
position encoding.

<a id="derivations"></a>
### 6.5. Derivations

`chainKeyWidth` and `periodKeyWidth` are each 16 octets under the fixed v1
capability width; these symbols denote HKDF output lengths.

```text
Root:  C[N-1] = HKDF(keyDerivationSecret, ROOT_INFO(family, geometry, w), chainKeyWidth)
Step:  C[i]   = HKDF(C[i+1],             STEP_INFO(family, geometry, w, i), chainKeyWidth)
Leaf:  P[i]   = HKDF(C[i],               LEAF_INFO(family, geometry, w, i), periodKeyWidth)
```

The `i` in `STEP_INFO` names the output chain key `C[i]`; its input is
`C[i+1]`.

<a id="operations"></a>
### 6.6. Operations

- **Root derivation.** Derive the root chain key `C[N-1]` for a window.
- **Backward step.** From `C[j]` derive `C[i]` for `i < j` in the same window by
  applying Step for `j-1, j-2, …, i`.
- **Period key.** From `C[i]` derive `P[i]`.
- **Expansion.** From `C[j]` derive `P[j], P[j-1], …, P[0]` in one backward
  walk, deriving each period key from the chain key retained at that position.
  See [Bounds](#bounds). A whole-window walk is the special case `j = N - 1`;
  expansion from a lower cutoff covers only that cutoff through position zero.
- **Cutoff.** A cutoff is `C[i]` together with its coordinate; it carries no
  separate capability kind (Section 13.1 states how a response files it).

<a id="deterministic-regeneration"></a>
### 6.7. Deterministic regeneration

The publisher retains or replicates the derivation secret and profile
configuration, not window chain keys or period keys: it regenerates a window's
root chain key from the secret and the complete window context, walks to a
requested position and reproduces the identical canonical `periodKey[t]`.

A publisher may cache derived keys, keyed by derivation secret, construction,
geometry, access group and coordinate; the protocol requires no persistent
chain-key storage.

Every producer that regenerates a canonical period key and wraps under it is
bound by the nonce and invocation discipline of
[spec-profile--period-keys.md](spec-profile--period-keys.md#content-wrapping-and-rollover),
whose counting domain spans all of them.

<a id="time-model"></a>
## 7. Time model

<a id="periods"></a>
### 7.1. Periods

A period coordinate denotes a half-open interval beginning at its label:

```text
t = 251023T1700  means  [17:00, 17:15) on 2025-10-23 UTC
```

under the `2/15` reference example. Period length is part of the resolved,
authenticated chain geometry.

<a id="windows"></a>
### 7.2. Windows

A chain window is a deterministic half-open interval `[start, end)`. Every
window has an independently derived root chain key from the publisher's
key-derivation secret and complete window context.

Chain geometry fixes how an aligned UTC day is divided into stationary windows
and how each window is divided into equal period positions. The wire pair is:

```text
chainsPerDay    positive integer, divides 1440
periodMinutes   positive integer, divides 1440 / chainsPerDay
```

From it the construction derives:

```text
windowMinutes = 1440 / chainsPerDay
N             = windowMinutes / periodMinutes      positions per window
```

The resolved geometry is valid only when `N ≤ maxPositionsPerWindow` from
[Bounds](#bounds).

The `2/15` setting (two twelve-hour windows, 48 positions each) appears in
examples only. There is no protocol default.

Windows are anchored at UTC midnight. Window `k` of a day starts at
`k × windowMinutes` minutes after midnight, `0 ≤ k < chainsPerDay`. Position
`i` of a window starts `i × periodMinutes` minutes after the window start,
`0 ≤ i < N`. The terminal position is `N - 1`.

A chain-bearing delivery or request MUST carry one publisher-selected, top-level
`periodGeometry` pair for every chain-bearing family. The pair has exactly
`periodMinutes` and `chainsPerDay`; no access-group, content-group, issuer or
per-key override exists. All chain operations in one delivery use that same
pair. Different deliveries may use different pairs, and retained keys from
both can coexist in a client cache.

The publisher, or its trusted key service, MUST configure the complete
`chainsPerDay` and `periodMinutes` pair for a family generation that uses the
canonical construction, including when it supplies only derived period keys.
An issuer may choose a shorter authorized cutoff or return period keys, but it
cannot choose different geometry for that family: doing so would derive
different key bytes from those used by the article.

Malformed or unsupported chain geometry fails at the scope Section 12.1 lists.
An actor that repackages a chain capability preserves its geometry. The pair
enters the KDF context and the `pc` BIND; JSON spelling and member order do
not change derived bytes. An issuer or
client MUST NOT infer geometry from labels, entry count or their spacing.

Every positioned chain key and every period key derived for one access-group
family in one chain-bearing message MUST come from the one family generation
that period-keys Section 5.5 requires per render; for a canonical generation
that is one derivation secret, one construction and one resolved geometry.

<a id="coordinate-labels"></a>
### 7.3. Coordinate labels

A chain-bearing family labels every coordinate on the wire as:

```text
YYMMDDTHHMM     UTC, fixed eleven characters
```

`YY` is the year within 2000 to 2099, the first `MM` is `01` to `12`, `DD` is
the day within that month, `HH` is `00` to `23`, and the final `MM` is `00` to
`59`. These field ranges, the real-calendar test, and the family-grid test are
normative. A label is on the family grid when its minute of day is a multiple
of `periodMinutes`.

The mapping between a label and the construction coordinate is:

```text
M           = minutes since 1970-01-01T00:00Z of the labeled instant
windowStart = M - (M mod windowMinutes)
position    = (M - windowStart) / periodMinutes
label(w, i) = format(w + i × periodMinutes)
```

`format` spells the labeled instant as `YYMMDDTHHMM`, each field zero-padded
to its width; it is the inverse of the mapping above.

Base period-key consumers admit `t` lexically only (period-keys Section 5.5); an
issuer selected for chain input applies this section's stricter admission
(Section 12.3).

The two-digit year bounds this profile's canonical construction at
2099-12-31. A deployment MUST select a successor chain-key profile with a
wider label before it emits a later coordinate.

<a id="chain-supply-and-window-rollover"></a>
## 8. Chain supply and window rollover

If the publisher chooses chain supply for both current and next windows,
that supply contains root chain keys for two independently rooted stationary
windows. Geometry describes derivation layout; it selects no
issuer grant duration and does not authorize a client for a whole window.

Inside one chain window, a client retaining a later chain position can derive
an earlier period key that an article needs. A later period key cannot do that.
At an independently rooted window boundary, a later-window chain key cannot
derive an old-window period key. An old supplied member can still serve an
authorized requested old wrap independently of the current/future horizon.
Without usable old supply, opening needs a retained matching key, another
complete route or an additional wrap supported by usable material.

A forward overlap wrap does not require another supplied chain key. For
example, an article can have a current period-key wrap supported by a current
window's chain source, and a next-window period-key wrap supported by an
ordinary sealed period-key member. The latter remains an ordinary period-key
route; supplying it entrusts that period key, not the next window's chain.
The publisher takes both period keys from the same construction generation,
even if it privately derives next-window chain material to obtain the overlap
period key. That overlap period key is the same key used when its coordinate
becomes current. A same-window overlap within a supplied chain's reach is
already derivable and does not create a distinct chain member.

Publisher selection keeps item-wrap coordinates, ordinary period-key supply
coordinates and positioned chain-source coordinates separate. Each explicitly
promised period-key acquisition route needs supply that can produce at least
one of the item's offered period keys, as the period-key specification defines.
A union of ordinary and chain members can satisfy that promise without every
wrap being reachable from a chain member alone. Other wraps may remain usable
only with retained capability. An independent item content-key route can also
complete the item without promising period-key acquisition. A chain-only
route cannot promise acquisition of a period key outside its supplied chain
reach.

<a id="chain-key-role-requirements"></a>
## 9. Chain-key role requirements

Base period-key duties are normative in
[spec-profile--period-keys.md](spec-profile--period-keys.md#base-period-key-requirements). The
duties below belong to the optional chain-key profile, which depends on the
period-key profile. A role is bound only by the chain-key duties it claims
or that trusted deployment configuration selects for a complete route.

The publisher may use the canonical construction for a family generation.
That private choice fixes the generation's ancestry but does not by itself
select a cross-role chain-key path. Publisher chain supply, issuer chain
input, request relay, issuer chain output and client derivation are distinct
duties. Period keys remain the dependency interoperability surface.

The role requirements are:

- A publisher generation that uses this canonical construction **MUST** derive
  every shared period key for that generation through it.
- For each issuer route, the publisher **MAY** supply period-key members, chain
  members or both. Period-key-only supply is a period-key path. Supplying chain
  members selects a chain-key supply duty for that route.
- Before a publisher emits chain-only period supply for a route the deployment
  relies on, trusted configuration **MUST** establish request relay and issuer
  chain-input support. An independently authored item content-key alternative
  is a separate complete alternative and is not forced through the chain path.
- For a chain-supplied period route, the completeness evidence
  [core Section 9](spec--core-protocol.md) requires is a chain member in
  `sealed.chainKeys` of a usable issuer block whose window contains the item's
  `(accessGroup, t)` wrap at or below the member's supplied position, reachable
  through a request path selected for relay and an issuer selected for chain
  input. The publisher **MUST NOT** count such a route as complete at
  publication, or at a later read coordinate for which the deployment promises
  a new unlock, unless each response form the route may select there can
  produce a capability for at least one of the item's wraps; it **MUST** author
  another selectable wrap or another complete route for any later new-unlock
  availability the deployment promises.
- A request path selected for relay **MUST** carry applicable source members
  unchanged and request desired unresolved article-wrap labels under Section
  12.4. It **MUST NOT** treat relay or requested labels as authorization.
- A client accepting period keys projected from relayed chain supply **MUST**
  resolve the associated request's geometry for that family and admit a
  returned period key only when it was independently presented as a period-key
  member or lies in a presented chain member's window for that family at or
  below that member's supplied position. This admission duty does not require
  chain derivation or retention. A projected period key needs no response
  geometry.
- An issuer selected for chain input **MUST** admit and process chain supply
  under this specification. It **MAY** project authorized period-key grants.
- An issuer **MAY** return a chain grant only when every derivable coordinate
  from the window start through its cutoff is authorized and the route's
  trusted configuration establishes that its clients accept and derive that
  response in the selected transport mode.
- A client selected for chain response **MUST** admit a returned cutoff only for
  a family the request presented, in the window of a presented chain member of
  that family and at or below that member's supplied position. Before it admits
  or retains a cutoff it **MUST** resolve the complete geometry pair from the
  immutable request captured for that response. A missing, malformed or unsupported
  captured pair admits no chain capability. Response metadata and later changes
  to the delivery MUST NOT supply or override that pair.
  It **MUST** then either retain a positioned chain key for bounded derivation
  or expand selected period keys (Section 13.2).
- Before using or retaining period or chain capability from a response, the client
  **MUST** validate `notDelivered` under
  [period keys Section 5.6](spec-profile--period-keys.md#family-reports-notdelivered).
  A chain-key entry counts as period capability for that section's family
  conflict check, including when the client does not support chain results.

A family generation that used the canonical construction stays compatible
with later chain delegation over its existing article wraps. A generation
that did not use it acquires no such ancestry later.

<a id="capability-and-configuration-model"></a>
## 10. Capability and configuration model

There is no deployment-wide `chainMode`. This version defines no request or
signed-assertion member that offers, discovers or negotiates client
chain-response support.

Relaying the extension members, the presence of `periodGeometry` in a request,
and successful opening of
a chain envelope establish nothing about client chain-response support. They
select or authenticate source coordinates, not the client's ability to consume
chain keys, under the issuer-decision invariant of
[spec--security-model.md](spec--security-model.md).

When trusted issuer and client configuration does not establish chain response
support, the issuer projects authorized period keys. When period-key output is
not selected for the issuer or is not sourceable from the supplied members, it
returns no reusable period capability instead of improvising a representation.
An endpoint that serves clients of different capabilities returns period keys
unless an authenticated or otherwise trusted client-population distinction
selects a chain-capable population. Defining such a distinction is deployment
work; this version adds no wire mechanism for it.

Out-of-band trusted issuer and client configuration selects the response
representation in this version. How a deployment records the selections
Section 9 names, onboards a publisher or ships its configuration is outside
this specification.

A **cryptographic capability** is key material whose bytes confer the authority
of Section 5. Implementation support, configuration and selection are distinct
([spec--profiles.md](spec--profiles.md) Section 2), and none is entitlement.
The chain-key profile depends on the period-key profile as
[spec--profiles.md](spec--profiles.md) Section 5 states. A configuration toggle
is not a profile.

<a id="publisher-to-issuer-supply"></a>
## 11. Publisher-to-issuer supply

The publisher supplies typed capability members. The
issuer's supplied ceiling is the union of the reach of its valid members in
the input collection selected under Section 13. The following example assumes
a deployment that deliberately selects both period-key and chain input:

```text
issuer capability collection
├── chainKey[71]  -> period keys 48 through 71
└── periodKey[80]       -> period key 80 only
```

This example intentionally withholds positions 72 through 79. It is one
composite ceiling, not two fallback routes.

<a id="period-key-supply"></a>
### 11.1. Period-key supply

Period-key members follow the base supply duty of period-keys Section 5.5; for
a canonical generation they are its canonical period keys (Section 9).

<a id="chain-supply"></a>
### 11.2. Chain supply

The publisher includes one positioned `chainKey` member for each
supplied window of an access-group family. The supplied position is normally
the window's root chain key; a lower position attenuates the issuer's
ceiling to the window start through that position.

<a id="collection-construction"></a>
### 11.3. Collection construction

The publisher follows the single-generation-per-family rule of
[period keys Section 5.5](spec-profile--period-keys.md#base-period-key-requirements)
for chain supply in each render. Replacement generations can coexist across
retained renders and in client caches. The following rules describe consumer
handling of presented candidate alternatives.

The issuer validates each member independently and computes authority from the
union of valid, selected members. A sealed member that fails invalidates that
member. A malformed or conflicting family collection, including
two positions from one window, invalidates that family's chain collection.
Several members at one position of one family are candidate alternatives at
that one position
([data format Section 2.3](spec--data-format.md#23-collections-of-named-records));
they do not conflict, and each counts toward the member bounds of Section 22. A
consumer MUST check positioned labels and the one-position-per-window rule
before checking envelope-value encoding or opening. Every syntactically valid
positioned label holds its window position even when its envelope is malformed
or fails opening.

Geometry failures take the scopes Section 12.1 lists. The issuer never
reinterprets a failed chain member as a period-key member, and it does not
silently select a period-key fallback route (Section 13).

<a id="extension-carrier-and-client-relay"></a>
## 12. Extension carrier and client relay

Publisher-to-issuer chain supply travels through the client request path as
two known extension members: the `periodGeometry` object and the
`sealed.chainKeys` capability collection. A client selects the relay capability
to carry them; relay is request-carrying support and does not make the client a
chain deriver.

<a id="document-member"></a>
### 12.1. Document member

A chain-bearing document carries one top-level `periodGeometry` context object
and keeps each issuer's chain-key collection in the existing
`sealed.chainKeys` location:

```json
{
    "periodGeometry": { "periodMinutes": 15, "chainsPerDay": 2 },
    "issuerData": [
        {
            "issuerName": "<issuerName>",
            "sealed": {
                "contentKeys": [],
                "chainKeys": [
                    { "accessGroup": "<accessGroup>", "cutoff": "<suppliedT>", "key": "<sealed chain-key bytes>" }
                ]
            },
            "keyId": "2025-10"
        }
    ]
}
```

A delivery carries `sealed.chainKeys` only when a selected issuer block uses
chain supply. Period authoring without selected chain processing omits
`periodGeometry`, even if the publisher privately used the canonical construction
to produce its period keys. A delivery MUST carry the complete pair for selected
chain processing when a cached chain can open it, even without a fresh
`sealed.chainKeys` source. An issuer block that
supplies only period keys has no `sealed.chainKeys` collection; the top-level
`periodGeometry` may also serve a sibling issuer block using chain supply.
The chain supply and complete-pair geometry are extension members under
[spec--data-format.md](spec--data-format.md) Section 8; a consumer that has not
selected chain relay or processing ignores them as unknown members under its
Section 2.

| Member | Type | Requirement |
| --- | --- | --- |
| `periodGeometry` | object | Top-level shared period context; complete pair for chain processing |
| `sealed.chainKeys` of an `issuerData` block | array | Optional chain-capability collection |

`periodGeometry` is a non-array object with these members:

| Member | Type | Requirement |
| --- | --- | --- |
| `periodMinutes` | number | Required positive integer for chain processing |
| `chainsPerDay` | number | Required positive integer when chain processing is selected |

A producer MUST omit `periodGeometry` when only period authoring is selected,
or emit exactly both members when chain processing is selected. The latter
includes a delivery opened by a cached chain without fresh chain supply. Null,
empty and partial objects do not supply a chain pair. A positive
integer here is a JSON number whose
mathematical value is an integer greater than zero, whatever host type a parser
stores it in and whether its JSON spelling has a fraction or exponent: `2`,
`2.0` and `2e0` admit the same value before Section 7.2 applies its bounds. The
`pc` BIND spells the value canonically (Section 12.2).

`sealed.chainKeys` holds records `{accessGroup, cutoff, key}`. Its `cutoff`
is `suppliedT`, the label of the supplied position, normally the window
terminal; Section 7.3 defines its grammar and grid admission and Section 11.3
the one-position-per-window rule. A family is the set of records that name one
`accessGroup` in one collection. Each sealed `key` is the 16-octet chain key at
`suppliedT`, sealed to the
issuer under the chain envelope BIND (Section 12.2) and spelled as a binary
string under data-format Section 2.2, in the delivery and in the request.

These scopes apply to a consumer that has selected the profile. Each failure
supplies nothing from its unit; a valid sibling stays usable under data-format
Section 7 unless a bullet below states a wider failure. Core Section 5 owns
request admission.

- An unknown member directly inside `periodGeometry` makes chain geometry
  unsupported. An old `accessGroups` override in a request is a whole-request
  admission failure under core Section 5; in a delivery it supplies no chain
  geometry.
- A present `periodGeometry` that is not a non-array object supplies no
  geometry: no chain family of that delivery or request has a resolvable pair.
- A malformed or unsupported pair (either member absent, null or not a positive
  integer, or the pair fails Section 7.2) supplies no chain geometry. No family
  override can restore it.
- In a request, a `sealed.chainKeys` that is not an array, or a record whose
  `accessGroup` is missing, is not a string or fails identifier rules, fails
  request admission under core Section 5.
- A family in `sealed.chainKeys` without the shared pair is a failed family,
  not an absent one: it supplies no chain candidate and selects no period-key
  alternative by itself.
- In a delivery, a `sealed.chainKeys` that is not an array, or one
  rejected under data-format Section 2.1, supplies no chain candidate for that
  issuer block; `sealed.contentKeys` and `sealed.periodKeys` stay structurally
  usable, and whether period-key members remain selectable after a chain
  failure is the union rule of Section 13.
- An element that is not a non-array object names no family and supplies no
  chain candidate; the consumer skips it, and its siblings keep their scope.
- An invalid sealed `key` under data-format Section 2.2 supplies no candidate
  at its coordinate; its `cutoff` still occupies its window for the
  one-member-per-window rule of Section 11.3, so a second member in that window
  fails the family.
- More than `maxChainMembersPerFamily` raw records fail that family; more than
  `maxChainMembersPerMessage` fail every chain family of that chain collection,
  one issuer block's `sealed.chainKeys` in a delivery or the request's. Such a
  failure reinterprets none of those members as period-key input.
- In a request, a family that fails the one-member-per-window rule or a member
  bound, and a member that fails label
  admission, yield no capability and no error entry; neither makes the request
  a whole-request failure.

<a id="chain-envelope-bind"></a>
### 12.2. Chain envelope BIND

The `pc` kind under `dca-bind-key-envelope` is the chain-envelope binding. It carries
the resolved geometry; base `c` and `p` binding bytes are unchanged.

```text
dca-bind-key-envelope | pc | renderId | accessGroup | suppliedT
            | chainsPerDay | periodMinutes
```

The line break and spaces in this display are not part of the value. Fields,
including the canonical decimal spelling of `chainsPerDay` and `periodMinutes`,
are encoded as
[spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md) Section 3.2
encodes every BIND field. `renderId` is the field of that section, and
`suppliedT` is the label of the supplied position. The publisher refuses to
seal a `pc` binding that lacks either integer, and the issuer refuses to open
it; there is no shorter `pc` form. The sealed payload is exactly the 16
chain-key octets. BIND is applied to the seal as for every kind (envelopes
Sections 4 and 5). The configured chain-key profile, not the envelope, fixes
how the opened chain key is interpreted.

Publisher separation rests on the registration-scoped opening key (core Section
6.3) and on separate opening keysets for mutually untrusted publishers
(envelopes Section 7). A copied `pc` envelope opened under a shared keyset
yields a window ceiling of up to `N` period keys, not one coordinate, so a
family that selects this profile is served only by a registration whose opening
keyset is not shared with a publisher it does not trust. The envelope is sealed
once per render; the capability it yields to a client is not render-bound.

<a id="request-member"></a>
### 12.3. Request member

A relay client selects `sealed.chainKeys` members for the access groups
required by the request, using the same unresolved-item and access-group
selection boundary as the base request path. It copies each selected label and
sealed value unchanged and carries the top-level `periodGeometry` object
unchanged. It does not derive, merge, or rewrite sealed members. Unselected
family records may be omitted.

Chain-only supply yields no capability through a request path without selected
relay or at an issuer without selected chain input.

An issuer without selected chain input ignores `sealed.chainKeys`,
`periodGeometry` and `requestedPeriodKeys` as unknown request members and parses
none of their names or labels. It processes an otherwise usable request through
its selected content-key and period-key sections; if those are all empty, the
request is malformed under core Section 5. Ignored members still count toward
the finite request limits that section requires.

An issuer selected for chain input validates the request's `periodGeometry`
before opening any envelope: its exact complete pair, divisibility, and
`N` within [Bounds](#bounds). It then opens each member under the BIND built
from the resolved context and the member's label. A member whose BIND does not
verify, whose label is off its family's grid, or whose family lacks a resolved
pair fails as a chain member (Section 11.3).

Each record of `sealed.chainKeys` with a grammar-valid `accessGroup` presents
that access group, even when its `cutoff` or `key` is malformed. A malformed
cutoff names no admitted source coordinate. A malformed key value is no usable
source capability and reaches no opening key; when its otherwise admitted
coordinate is authorized, the issuer reports `unseal_failed` there under core
Section 7.1 without opening that value. Family presentation alone authorizes
neither an opening nor an error. Valid sibling families retain their own
admission scope. An empty collection presents no family. Each
admitted member presents the coordinate `(accessGroup, suppliedT)`.
A member's derived result coordinates run from its window start
through its supplied position under the geometry the request resolved (Section
5.2), and form that member's part of the admissible result set (core Section
6.1).

<a id="requested-article-periods"></a>
### 12.4. Requested article periods

A selected chain request MAY carry the unsigned top-level member
`requestedPeriodKeys`, a non-empty array of records `{accessGroup, periods}`.
Each record is a non-array object whose `accessGroup` is an access-group
identifier and whose `periods` is a non-empty array of canonical period labels.
A relay serving unresolved items MUST populate it from the period-key wraps it
wants to open, taking the union separately per group. Producers SHOULD emit one
record per group and sort and deduplicate each array; raw labels count against
the maxima. Several records for one `accessGroup` request the union of their
`periods`; repeating a label changes nothing. This union is the normalization
rule for this collection, not a reading of the former object form.
Several items, groups and wrap alternatives need not share one render-level
coordinate. `issuedAt` is not a wrap selector. Hints do not enter an envelope
BIND.

A selecting issuer MUST count raw labels across all records before
deduplication, enforce the selector input maxima in Section 22, and validate
every label. Invalid shapes, identifiers, labels or excess raw counts are
whole-request structural
failures before policy or opening-key work. For an admitted source family with
valid geometry, an off-grid desired label has the same failure scope.
Duplicates and arbitrary array order are accepted; the issuer deduplicates
and sorts before deterministic selection. A
canonical target outside supplied windows is well-formed but unavailable. An
invalid source family retains its existing scoped failure and is not repaired
by a hint. A hint naming no admitted chain source presents no family and
authorizes no opening.

For the desired-label grid check, an admitted source family is a family with
at least one record whose geometry resolves and whose collection passes the family-
and message-scoped conditions, including one position per window and
member-count bounds. Individual member label or envelope failures retain their
member scope and do not by themselves change that collection's admission.
Desired labels are checked against its resolved grid even if no individual
member ultimately yields capability. A family that fails collection or
geometry admission keeps that scoped failure; its desired labels do not turn
it into a whole-request failure merely by being off-grid.

An omitted member requests no explicit article coordinates; the issuer MUST
NOT infer them from the render timestamp. A hint alone cannot make an empty
key-bearing request usable, select a different source route or enlarge the
associated request's admissible result set.

<a id="issuer-decision-and-response"></a>
## 13. Issuer decision and response

Opening an envelope authenticates its access group, geometry and supplied
position against the resolved context. Successful opening supplies sourceable
key authority, not entitlement (core Section 2.3).

An issuer configuration may assign a publisher relationship or family to a
chain-owned period route. On that route, absent, invalid or unrepresentable
chain input does not silently select the base period-key route. On that route,
the issuer selects desired article coordinates separately from any optional
current-and-future horizon, as specified below. Period-key input remains
available through a separately configured base route, and a valid chain route
may project its selected reach into ordinary period keys. A deployment that
deliberately selects a union of period-key and chain input must define that
union before opening either representation; a failed or removed member does not
select it.

<a id="chain-route-periodcount"></a>
### 13.1. Article selection and optional future grants

The issuer MUST authorize the full reach of each returned capability as core
Section 6.2 requires; an unsigned desired label (Section 12.4) is a candidate
output, never that authorization. Policy may permit older articles or the
entire bounded prefix; earlier positions are not excluded merely because time
passed.

A trusted policy decision also MAY select `futurePeriodCount`, a non-negative
integer maximum for optional consecutive current-and-future coordinates. This
is an internal policy concept, not a request or response field. Zero means no
future grant; it does not deny independently authorized article coordinates,
including future article labels. A policy that limits forward reach MUST enforce
that limit when authorizing each article coordinate, independently of
`futurePeriodCount`. Complete family denial is a separate policy decision.

A family or member rejected as malformed MUST NOT establish the valid-supply
condition for `unavailable`. A well-formed desired coordinate outside the reach
of otherwise valid supplied chain material may qualify only after independent
policy authorization, when no capability is delivered for the family. An
authorized source that fails cryptographic opening follows the core error
rule, not `unavailable`.

Before opening any selected source, the issuer MUST authorize production of at
least one useful capability from that particular admitted source. Permission
to derive an old period key can justify opening a later supplied chain member;
it does not authorize returning that member's entire prefix. Opening uses the
member's original suppliedT and geometry in pc BIND. Requested coordinates
MUST NOT substitute for suppliedT.

First select desired article coordinates that policy permits and actual
source members can produce. A member can produce a target only in its own
independently rooted window and at or below its supplied position: the issuer
MUST NOT produce from a chain member a coordinate outside that member's
admissible result set (core Section 6.1), in another window or from an absent
member. Successful
production also requires envelope opening. An absent old-window member cannot
be replaced by a later independent window or a different current generation.
The issuer MUST NOT require current-time supply to select an otherwise usable
old article target.

Separately, the issuer MAY select its authorized future horizon, beginning at
one issuer-captured current coordinate aligned down to the family's period
grid. A client clock grants nothing. Clamp the horizon to supply and output
bounds before iteration. A selected future horizon MUST contain at most
`maxPeriodKeysPerFamily` coordinates; this ceiling does not require a future
grant. An unavailable or unauthorized coordinate stops that
consecutive horizon. A future gap MUST NOT suppress independently selected
article targets. An overlapping article/future coordinate yields one key.

For projected period-key output, the issuer MUST reserve capacity for article
targets across every family before selecting optional future keys. Article
selection is ordered by (accessGroup, t) byte order; remaining future selection
uses the same order. Both count against projected output maxima. The selector
input maxima do not guarantee that the actual article candidates and ordinary
fallback fit those capacities; mandatory output overflow is refused under
Section 22.1. A larger optional future count is clamped, not an error. Denied, absent or failed alternatives create
no promise that every requested item will open.

Response form is independent of desired coordinates, source reach and policy
permission. Under a selected period-key-capable response agreement, the issuer
projects the permitted selected periods; the client needs no chain derivation.
Under an already selected chain response agreement, the initial candidate cutoff
is the latest selected target in each supplied window. The issuer MAY narrow
that cutoff to an earlier selected target whose complete prefix is permitted;
targets beyond that cutoff receive no capability from this chain grant. The
issuer MUST check every position from that window's start through the returned
cutoff against policy and valid supply.
If it is too broad, project permitted period keys only when the selected
response agreement permits them; otherwise return no such capability. A
mid-window subscriber whose earlier prefix is denied receives no chain grant;
family reporting still follows period-keys Section 5.6 rather than treating an
individually allowed article as a whole-family denial. On a
chain-owned route the issuer selects period keys or chain keys for one family,
not both; a deployment that selects a union of the two defines that union
before opening either representation (Section 13). Do not invent mixed grammar
or change transport.

A well-formed but unavailable target and a denied target yield no key, not a
cryptographic error. An admitted, authorized chain member that cannot be
opened, or whose opening key is retired, is reported at the core error
coordinate `accessGroup "|" suppliedT` with the core error codes; the entry
names the supplied member, not a requested or projected coordinate. A
period-key member and a chain member of one family can share that coordinate,
and the entry does not name the source kind. The issuer emits an opening error
there only when no admitted, authorized source sharing it produced a delivered
capability and no key occupies it. Complete denial and a no-key family with
unavailable valid supply for an independently authorized article or future
selection remain subject to the family reports of period-keys Section 5.6,
which exclude a family that received any period capability. Missing old supply
can qualify as `unavailable` even with no future grant.

Retained keys do not expire at the future horizon; cache eviction is separate
host policy.

Period keys projected from chain supply travel in `keys.periodKeys` without a
marker. A chain grant keeps its positioned chain keys in the `keys.chainKeys`
location as records `{accessGroup, cutoff, key}`. For the member bounds and one-position-per-window rule in Section
12.1, `keys.chainKeys` is also a chain collection; response entry admission
follows Section 9 and the selected response binding.
The issuer-core result holds raw chain-key bytes there; a selected
client-bound response binding replaces each key entry with its wrapped object.
The client interprets every returned chain member under the complete pair
captured from its associated request; the response carries no geometry echo.
In direct transport mode, a
response mixing an item content key, period keys and a chain key has
this enclosing shape:

```json
{
    "keys": {
        "contentKeys": [
            { "contentName": "<contentName>", "key": "<base64url(content key)>" }
        ],
        "periodKeys": [
            { "accessGroup": "<accessGroup>", "period": "<t>", "key": "<base64url(period key)>" }
        ],
        "chainKeys": [
            { "accessGroup": "<accessGroup>", "cutoff": "<cutoffT>", "key": "<base64url(chain-key bytes)>" }
        ]
    }
}
```

The response uses the geometry of its exact associated request. The issuer MUST
emit
`keys.chainKeys` exactly when it has selected stock chain response and returns
at least one stock chain grant. The issuer MUST NOT emit root `periodGeometry`
for stock chain grants. Before opening or retaining a chain key, the client MUST
validate the complete pair captured from the associated request and use that same
pair throughout admission and retention, including after asynchronous key opening.
Geometry metadata in a response has no authority. A captured request with a
missing, null, partial or overridden pair admits no chain key. These rules apply
to direct and client-bound responses, including mixed item, period and chain grants.

The `cutoff` field above holds an ordinary canonical period coordinate `t`:
the position of the returned chain key. It is the record's coordinate, not an
extra key identifier; the issuer selects its permitted cutoff independently of
unsigned requested article labels. Several records at one `(accessGroup,
cutoff)` are candidate chain keys at that one position. Neither the selected response `t` nor the cutoff
concept enters base period-key `p` BIND; a period-key envelope always binds its
own `t`.

<a id="client-retention-strategy"></a>
### 13.2. Client retention strategy

A chain-capable client may retain a positioned chain key and derive period keys
lazily, or expand selected period keys and discard the chain key; this profile
mandates neither and requires no persistent storage. A period key the client
correctly derived from an admitted chain capability and retains is an ordinary
period capability under the cache rules of period-keys Section 5.5: chain
geometry and construction do not condition its use, so it opens a matching
period-key-only render that omits `periodGeometry`.
Neither strategy
requires deriving or retaining every period the grant reaches.

<a id="capability-combinations"></a>
## 14. Capability combinations

This section is informative.
[guide--chain-keys.md](guide--chain-keys.md) tabulates supply, relay and
response combinations; Sections 9, 10 and 13 state the rules.

<a id="compatibility-boundary"></a>
## 15. Compatibility boundary

This section is informative. Section 9 states compatibility with later chain
delegation; Section 19 states migration from independently generated period
keys.

Enabling chains does not require advance derivation in a period-key-only
deployment. A publisher can start with independently generated period keys,
then switch its new renders to a new canonical construction generation.
Retained old keys do not open those new wraps; the client follows its ordinary
candidate attempts and unresolved-item acquisition path. Old keys can still
open matching old renders. Neither a cache flush nor a wrapped translation
from new material to old period keys is required.

Publisher and issuer activation can be staged. The publisher can supply both
ordinary period keys and chain sources for its new generation while existing
routes continue to use the ordinary members. A configured relay and issuer
can later consume the already-carried chain sources without changing the
article wraps or publisher generation. That issuer can return ordinary period
keys, or select chain output when its trusted response agreement permits it.
The issuer-input switch does not imply a client-output switch. Until usable
relay and issuer chain-input support are established, the publisher retains
a complete ordinary supply route for operations relying on it. Mere chain
presence is not capability negotiation or authorization.

<a id="worked-examples"></a>
## 16. Worked examples

This section is informative. The examples use the `2/15` reference geometry and
day-absolute positions: `P72` is the period key at position 72 of the day and
`C95` the chain key at position 95.

<a id="chain-key-issuer-and-period-key-only-client"></a>
### 16.1. Chain-key issuer and period-key-only client

The publisher seals the root chain key `C95` to issuer B for the 48-position
window `[48,96)`. The client has selected the relay capability and forwards that
issuer material without deriving from it. Issuer B authorizes coordinate 72,
derives `P72`, and returns that period key. The client unwraps with `P72` as an
ordinary period key (period-keys Section 5.5).

<a id="future-period-key-grant-inside-a-window"></a>
### 16.2. Future period-key grant inside a window

A subscription begins at coordinate 72 inside a window that began at 48. The
issuer can return `P72` in advance without granting 48 through 71. Returning
`C72` grants every coordinate from 48 through 72, so the route returns it only
when policy authorized that whole reach.

If an article rendered before the subscription start was already wrapped under
`P72`, the future period key opens it immediately. A period key opens whatever
the publisher wrapped at its coordinate, regardless of publication time.

<a id="counts-and-efficiency"></a>
## 17. Counts and efficiency

This section is informative.
[guide--chain-keys.md](guide--chain-keys.md) compares key counts for period-key
and chain supply.

<a id="multiple-access-groups-and-issuers"></a>
## 18. Multiple access groups and issuers

This section is informative.
[spec-profile--period-keys.md](spec-profile--period-keys.md#multiple-access-groups-and-issuers)
states the rules; every chain context binds `accessGroup` (Section 6.4).

<a id="generation-identity-and-migration"></a>
## 19. Generation identity and migration

For an article, the client first considers ordinary period-key candidates
under the cache partition of period-keys Section 5.5: period keys an issuer
returned and period keys derived locally from an admitted chain capability
(Section 13.2). Derivation provenance MAY be retained as metadata; it
conditions no use (Section 13.2).

For a chain-bearing article, the client may additionally derive candidates
only from the one chain partition selected by that article's resolved geometry
under the configured profile. It MUST NOT search unrelated retained geometry
partitions for that derivation. A retained chain key remains subject to its
construction, window and cutoff.

A cache of retained chain keys partitions derivation by:

```text
publisher security namespace (period-keys Section 5.5)
  × access-group family (with the configured issuer partition, if any)
  × chain-key profile and canonical construction
    (the route's configuration for that family generation states them;
     no identifier travels)
  × chainsPerDay
  × periodMinutes
```

The derivation secret is not a public partition selector in this profile.
Different derivation-secret bytes at one coordinate remain bounded rival candidates
inside the applicable partition.

Without a generation selector, rollover can require deriving more than one
candidate period key for a target `t`; retained derived keys join the ordinary
candidate trial of period-keys Section 10.

Migration from independently generated earlier material needs explicit
candidates from retained earlier messages or client caches, or a retirement
boundary.

Earlier ciphertext at an admitted coordinate still needs key material from its
own generation; sharing a label alone does not make rival keys equal.

<a id="keyderivationsecret-rollover"></a>
### 19.1. `keyDerivationSecret` rollover

Secret replacement starts new family generations (Section 5.1). Old and
replacement generations coexist while their material remains usable, with no
derivation-secret or generation selector on the wire; rival candidates are
resolved as period-keys Section 10 describes.

Changing `chainsPerDay` or `periodMinutes` starts a new family generation
(Section 5.1) and lands in a different cache partition through the resolved
pair. Receiving new geometry, a new profile or a rival candidate is not a
deletion command: retained old renders may still need old material.

Rollover is smooth: new renders and unlocks work under replacement material
without a cache loop or a dependency on an old period key. This construction
does not promise no-new-unlock behavior across a generation boundary; a client
with no matching new-generation candidate unlocks the new render once.

<a id="capability-lifecycle"></a>
## 20. Capability lifecycle

[spec-profile--period-keys.md](spec-profile--period-keys.md#capability-lifecycle) states the two
lifecycle actions common to every period key: retiring acceptance of published
issuer material, and the impossibility of retiring client-held authority. This
profile adds a third:

1. **Deleting a publisher derivation secret** stops the publisher
   from regenerating window chain keys and period keys for every dependent
   family generation. It does not erase chain keys already sealed into retained
   issuer carriers, and it does not revoke authority already sealed for an
   issuer or delivered to a client. Regeneration for old generations survives
   only while the old secret is retained under an explicit lifecycle policy.

<a id="deployment-retirement-contract"></a>
### 20.1. Deployment retirement contract

The protocol selects no universal artifact-retirement mechanism and no
universal render expiry. Before a deployment removes chain support from a
family, an issuer route or a client population, it follows this order:

1. stop producing artifacts that depend on the capability being retired:
   chain-only issuer supply, chain grants, or renders whose only issuer route
   is chain-only;
2. then either republish or invalidate the dependent artifacts, expire their
   acceptance under a defined render-age policy, or keep the old route
   supported until the artifacts have left every cache; and
3. only then retire the consumer.

New period-key-only renders do not retire old chain-only markup by themselves.
The deployment chooses the mechanism in step 2 that satisfies this profile's
obligation.

<a id="failure-and-downgrade-principles"></a>
## 21. Failure and downgrade principles

This section is informative. Sections 11.3, 12.1, 12.3, 13 and 22 state the
failure rules.

<a id="bounds"></a>
## 22. Bounds

Every chain operation is bounded by the resolved geometry and by the fixed v1
protocol maxima below. A producer MUST stay at or below them. A consumer
that reaches chain-key admission applies the handling stated below; a
deployment MAY enforce a stricter finite resource cap and reject earlier, but
that local cap does not change whether the peer's chain message conforms to
this profile.

<a id="protocol-maxima"></a>
### 22.1. Protocol maxima

| Constant | Value | Bounds |
| --- | --- | --- |
| `maxPositionsPerWindow` | 288 | `N = (1440 / chainsPerDay) / periodMinutes` |
| `maxChainMembersPerFamily` | 2 | raw chain records for one access group in one chain collection in one message |
| `maxChainMembersPerMessage` | 16 | raw chain records across all access groups in one chain collection in one message |
| `maxPeriodKeysPerFamily` | 288 | distinct chain-projected period-key candidates returned for one access-group family; coordinates in one family's selected future horizon |
| `maxPeriodKeysPerResponse` | 512 | period keys across all families in one response |
| `maxRequestedPeriodsPerFamily` | 288 | raw requestedPeriodKeys labels for one family, across its records |
| `maxRequestedPeriodsPerRequest` | 512 | raw requestedPeriodKeys labels across the request |

The two period-key rows are independent constants: the family value bounds
chain-projected response output, the positions value bounds geometry.

An issuer MUST count the actual distinct period-key candidates after projection
and duplicate-key removal, not only the selected labels. Different key values
at one coordinate count separately. The family output maximum applies to
chain-projected families; it does not add a family limit to ordinary period-key
fallback. The response output maximum counts all ordinary `periodKeys` records,
including fallback families, but not errors, chain-key records or the dedicated
content-group response member. If either output maximum would be exceeded, the
issuer MUST refuse the whole exchange with `too_many_entries`, without
returning sibling keys, trimming candidates or silently omitting families.
This selected-profile finite output processing-limit refusal is a whole-request
failure under core Section 8 and HTTP binding Section 3.4 (HTTP 4xx); it does not
authorize conditional fallback. Invalid trusted policy grants remain policy
faults rather than output-limit refusals.

Member-count failures take the scopes of Section 12.1.

Section 12.4 states the selector-count rejection. A client needing more targets
uses bounded requests or a bounded subset; no automatic retry or one-response
success guarantee follows.

A client MUST NOT infer a different client limit from period keys arriving on a
route that also selected chains. These maxima constrain the chain-capable
issuer's selection and response construction, not the base period-key wire
shape; a chain family left with no capability is omitted under core Section 7.

`N` is the number of positions in one window and the longest backward walk;
`1/5` and `5/1` reach the maximum `N = 288`.

Expanding one member (Section 6.6) costs at most `N - 1` Step and `N` Leaf
derivations, `2N - 1` HKDF invocations. Deriving every period key by repeating
the walk from the cutoff is quadratic and is not a conforming expansion
algorithm. Full expansion of one message costs at most
`maxChainMembersPerMessage × (2N - 1)` HKDF invocations, 9,200 at the v1
ceilings; the member maximum bounds carrier and opening work even when clamps
return fewer keys.

<a id="local-retention-policy"></a>
### 22.2. Local retention policy

The profile fixes no numeric chain rival bound. A host MUST keep finite
bounds on retained chain rivals and on combined ordinary period-key rivals,
and a finite bound on candidate trials for one operation. The period-key
bounds of period-keys Section 5.5 cover returned and locally derived period
keys together, across sources and storage views. Their numeric values are
local availability and resource policy; they do not affect wire validity. The client MUST bound
the combined trials across ordinary and additionally derived candidates; it
MUST NOT give each storage view an independent unlimited trial budget. At a
local rival ceiling, the client admits the newly returned candidate and
evicts an older one.

An admitted capability stays available to its obtaining operation as
period-keys Section 5.5 requires, also while a chain grant is expanded or
promoted into reusable period storage and when capacity eviction removes an
expanded coordinate: the client may keep an operation-private derived key or its
usable admitted chain source, and a pending-to-retained transition MUST NOT
leave the obtaining operation with neither. Acceptance of the retained carrier
alone does not ensure that a chain-only route can return the key after
current-coordinate or window rollover.

## 23. Settled design choices

This section is informative. The sections this document cites carry each
decision; [guide--chain-keys.md](guide--chain-keys.md) explains them.

<a id="security-considerations"></a>
## 24. Security considerations

<a id="capability-monotonicity"></a>
### 24.1. Capability monotonicity

Moving from a period key to a positioned chain key broadens authority. The
resolved geometry and the cutoff label make that reach visible to issuer policy
and to client response selection.

The publisher chooses window geometry and per-issuer supply treating every
position of a supplied prefix as reachable, including copies of renders kept
outside its cache; to exclude earlier positions it roots a separate window, or,
when the response agreement permits period-key output, the issuer returns
period keys (Section 13.1).

<a id="window-confinement"></a>
### 24.2. Window confinement

The construction relies on independently derived root chain keys and
domain-separated context to confine derivation to its access group, profile,
geometry and window. Publisher separation additionally depends on the
publisher-scoped derivation secret and the cross-namespace non-reuse rule in
Section 6.2; publisher identity is absent from the construction context.
Client-side stopping rules add no cryptographic confinement.

<a id="publisher-and-issuer-compromise"></a>
### 24.3. Publisher and issuer compromise

Publisher `keyDerivationSecret` compromise can regenerate the corresponding
generations' window chain keys and period keys for every derivable window
covered by that key-derivation secret and profile. Issuer chain-key compromise
exposes only the window-start-through-position range it was supplied; period-key
issuer material limits exposure to supplied coordinates.
[spec--security-model.md](spec--security-model.md) states which effects are
protocol-boundary failures and which are defense-in-depth concerns.

<a id="response-transport"></a>
### 24.4. Response representation

An issuer MUST NOT return a chain key on a route whose trusted configuration
requires non-extractable custody of delivered period keys (response-binding
Section 5). A client-bound chain key opens to its 16 octets, which the client
uses for Step and Leaf, so the chain key and its derived period keys are bytes
to application code; client-bound transport does not change the grant's reach
(response-binding Section 6). The stricter non-extractable-custody condition is
a trusted deployment duty, not a wire signal or an automatic engine/agreement
check; selecting client-bound transport alone does not impose that condition.

<a id="work-amplification"></a>
### 24.5. Work amplification

No request causes unbounded backward derivation, period-key expansion,
rival-candidate trial or response construction; [Bounds](#bounds) names the
limits.

## 25. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function](https://www.rfc-editor.org/info/rfc5869)
- [DCA period-key capabilities](spec-profile--period-keys.md)
- [DCA conformance profiles](spec--profiles.md)
- [DCA data format](spec--data-format.md)
- [DCA content protection](spec--content-protection.md)
- [DCA sealed key envelopes](spec--sealed-key-envelopes.md)
- [DCA core protocol](spec--core-protocol.md)
- [DCA response binding](spec--response-binding.md)
- [DCA security model](spec--security-model.md)

## 26. Informative References

- [DCA period-key design companion](guide--period-keys.md)
- [DCA chain-key extension design](guide--chain-keys.md)
