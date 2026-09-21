# DCA period-chain construction and delegation

Status: Public Working Draft

## Abstract

This section is informative.

This specification defines derivable authority over one period-key family:
`periodChainKey[t]` derives the exact leaf for `t` and earlier positions inside
one independently rooted chain window. The exact leaf itself, `periodKey[t]`,
keeps its base exact-period meaning.

A publisher that uses the period-chain profile's canonical construction for
a family generation creates a chain-bearing family generation and derives its
canonical exact leaves.
It may delegate selected exact leaves to restrict an issuer to specific
coordinates, or delegate positioned chain state to give the issuer a compact
ceiling over many coordinates. A chain-capable issuer may return exact leaves to
an exact-only client or return a compact chain position when the complete range
from the window start through that position is authorized and the route's
trusted configuration establishes that its clients and transport accept it. A
period-capability route that does not select chain supply carries exact keys
only.

Both delivered forms are capability shapes over one family generation and the
same article wraps. A generation using this profile's canonical construction
derives its leaves through that construction. An exact-only interoperable path
exposes ordinary exact leaves and no chain state; private use of the canonical
construction behind those leaves does not by itself select the period-chain
profile.

<a id="scope-and-status"></a>
## 1. Introduction

This document defines the optional period-chain profile
`dca-period-chain-v1`. The profile depends on `dca-v1-exact-period` and fixes
one canonical construction that derives exact `periodKey` leaves from
positioned chain state. It also defines the construction's window geometry,
coordinate labels, carrier, envelope binding, response member, bounds and role
requirements. Construction and delegation stay together here.

[spec--period-keys.md](spec--period-keys.md) defines the exact `periodKey[t]`
capability that this construction produces and the base exact-period
requirements every role meets before a selected period-chain duty can operate.
This document
imports that leaf meaning and adds no second definition of it. An exact-only
issuer or client does not need this document; a publisher privately using the
canonical construction does.

The profile's canonical construction and wire transcript are frozen for
conformance work while the surrounding text remains a Public Working Draft:
the construction transcript, geometry parameter rules and context encoding,
and label grammar change only through a new profile identifier; the carrier,
`dca-bind-v1|pc` grammar and response member evolve through their own versioned
grammar, which by itself changes no leaf bytes; and the protocol maxima are fixed by
[Bounds](#bounds). Editorial text around that frozen surface may still change.
Construction requirements bind a publisher that uses the canonical
construction. Cross-role requirement words bind a role only once it has
selected the applicable profile duty. A conformance claim that includes that
duty waits on published conformance evidence.

The model:

- exact `periodKey` is the base capability of the exact-period profile and the
  interoperability floor for every role that implements it;
- a publisher may use the period-chain profile's canonical construction for
  one family generation,
  and then derives every shared exact leaf of that generation from its chains,
  so exact-only and chain-capable issuers open the same article wraps;
- derivable `periodChainKey` is the profile's capability; and
- issuer chain input, issuer chain output, client relay and client derivation
  are four separately selectable capabilities. A capability the profile
  defines is not a capability every actor implements.

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

This profile adds to the goals of
[spec--period-keys.md](spec--period-keys.md#design-goals):

1. **Expressive delegation.** The publisher and issuer should be able to grant
   exact, sparse, scheduled, or compact cutoff-based authority without redesigning
   article encryption for each policy.
2. **Compact broad supply.** Publishers should not need to seal hundreds of
   exact period keys for an issuer intentionally trusted for a whole window.
3. **Narrow authority when wanted.** A publisher should be able to withhold
   derivation reach and give an issuer only selected exact coordinates.
4. **Capability combinations that compose.** A chain-input issuer should be
   able to serve an exact-only client. One exact-only actor should not force every
   other actor onto the least efficient supply form.
5. **Deterministic, debuggable time geometry.** Period and window boundaries
   should be reproducible across implementations and visible in test vectors.

<a id="non-goals"></a>
## 3. Non-goals

This section is informative.

In addition to the non-goals of
[spec--period-keys.md](spec--period-keys.md#non-goals), this document does not
define arbitrary range trees, group-derivation trees, or multi-recipient
public-key envelopes.

<a id="actors-and-trust"></a>
## 4. Actors and trust

This section is informative. The actors are those of
[spec--period-keys.md](spec--period-keys.md#actors-and-trust). The duties below
apply once a role implements or selects an applicable period-chain profile
duty; [Period-chain role requirements](#period-chain-role-requirements) states
them normatively.

<a id="publisher"></a>
### 4.1. Publisher

The publisher chooses the period geometry, the independently rooted windows, and
which capability ceiling each issuer receives.

A publisher that uses the period-chain profile's canonical construction for a
family generation constructs the canonical chain and derives every shared
exact leaf from it. That complexity is acceptable because DCA already requires
the publisher or its trusted key service to create content keys, wrap them,
prepare issuer material, and sign render evidence.

The requirement is expressed in externally verifiable terms. A rendering
component need not contain the KDF itself if a trusted publisher key service
supplies conforming outputs.

<a id="client"></a>
### 4.2. Client

A client may select relay of the period-chain extension member without
implementing chain derivation. A relaying client copies the known extension
members unchanged; relay never requires the client to understand issuer
plaintext. A client that selects neither chain relay nor chain derivation is a
valid exact-period client and cannot carry chain-only issuer supply.

<a id="key-and-capability-model"></a>
## 5. Key and capability model

An exact leaf `periodKey[t]` has the meaning
[spec--period-keys.md](spec--period-keys.md#periodkeyt) gives it. This section
adds the generation facts the profile fixes, the derivable form and its reach.

<a id="generation-and-window-identity"></a>
### 5.1. Generation and window identity

A family generation that uses the canonical construction fixed by
`dca-period-chain-v1` additionally fixes,
beyond the base facts in
[spec--period-keys.md](spec--period-keys.md#period-key-family-generation-and-window-identity):

- the publisher's derivation secret (`keyDerivationSecret`);
- the period-chain profile and its canonical construction; and
- its resolved period/window geometry.

One derivation secret MAY be the retained input for several access-group family
generations. Root contexts keep logical families separate when one retained
input serves several generations; the retained input is not a logical-family
identifier.

After this pre-release canonical-width settlement, a derivation-construction
change requires a new period-chain profile identifier, not merely new secret bytes.
A delivered-width change requires a new suite/specification version.
Secret replacement starts new dependent family generations, even when profile
and geometry remain unchanged. A profile change likewise starts a new family
generation and requires the recipient and cache to retain which construction
interprets the capability. A geometry-value change starts a new family
generation; changing geometry parameter rules or their context encoding
requires a new period-chain profile identifier.

A window is a deterministic subdivision *within* one family generation, not a
new family or generation. Adjacent daily windows, for example, use
independently derived terminal states under the same generation. Replacing the
key-derivation secret, period-chain profile, or geometry values starts a new
family generation, even when `(accessGroup, t)` labels remain the same.

<a id="periodchainkeyt"></a>
### 5.2. `periodChainKey[t]`

`periodChainKey[t]` is positioned derivation-capable authority within one
independently rooted window. A holder can derive leaves from the window start
through `t`. It produces:

- the canonical `periodKey[t]` leaf; and
- preceding chain positions and their canonical leaves down to the beginning
  of that window.

It cannot derive a later position or cross into another independently rooted
window.

The same positioned-state capability may occupy two operational roles:

- a **supplied ceiling** is the state the publisher gives an issuer; it is
  normally the terminal/root state, but a lower supplied position is valid; and
- a **cutoff** is the positioned capability returned by an issuer to a client,
  deriving from that cutoff back to the window start.

The terminal/root state is only `S[N-1]`; terminal and cutoff are not separate
wire key types, and there is no wire `root` or `anchor` key type.

<a id="capability-reach"></a>
### 5.3. Capability reach

```text
direct contentKey
    opens one content item in one render

periodKey[t]
    opens all matching wraps at one (family generation, t)

periodChainKey[t]
    opens matching wraps from the start of its independently rooted
    window through t
```

Metadata cannot narrow the cryptographic reach of raw chain state. If a client
receives `periodChainKey[t]`, policy must authorize everything its bytes can
derive under the selected profile. An exact leaf yields no chain state:
possessing every leaf of a range does not make that range's chain position
derivable.

<a id="canonical-construction"></a>
## 6. Canonical construction

This section defines the one canonical construction fixed by
`dca-period-chain-v1`. Its chain state and exact leaf are each exactly 16
octets, and its publisher-retained `keyDerivationSecret` remains 32 octets. It
produces the exact leaves of
`dca-v1-exact-period` in [spec--profiles.md](spec--profiles.md).

The publisher selects this construction for a family generation in trusted
route configuration, under
[Capability and configuration model](#capability-and-configuration-model).
It never selects a second width. A secret replacement keeps the profile.
After this pre-release settlement, any transcript, KDF or context-encoding
change requires a new construction identifier; changing delivered width
requires a new suite/specification version. The identifier is not a wire member.
This profile retires the pre-release 32-octet construction and alternate
compact identifier, with no compatibility alias or length-based fallback.

<a id="model"></a>
### 6.1. Model

```text
S[N-1]  = Root(keyDerivationSecret, family, geometry, windowStart)
S[i]    = Step(S[i+1], family, geometry, windowStart, i)     0 ≤ i < N-1
P[i]    = Leaf(S[i],   family, geometry, windowStart, i)     0 ≤ i < N
periodKey[t] = P[position(t)]
```

`S[i]` is the positioned chain state at position `i`; `S[N-1]` is the window's
terminal state. `P[i]` is the exact leaf. No role uses chain state directly as
an AES wrapping key.

<a id="inputs"></a>
### 6.2. Inputs

| Input | Form |
| --- | --- |
| `keyDerivationSecret` | exactly 32 octets, generated or provisioned with full-strength randomness within one publisher site/security namespace |
| `accessGroup` | an [`identifier`](spec--data-format.md#21-identifiers), 1 to 64 characters, compared byte for byte |
| `chainsPerDay`, `periodMinutes` | the resolved pair from [Windows](#windows) |
| `windowStart` | minutes since 1970-01-01T00:00Z of the window start |
| `position` | `0 ≤ i < N` |

A logical family is the reusable lineage for one publisher security namespace
and access group.

A derivation secret (`keyDerivationSecret`) is one publisher-scoped, retained
32-octet input with a publisher-managed retention, replacement, and deletion
lifecycle. One derivation secret MAY serve several access-group family
generations inside the same mutually trusted publisher site/security namespace
because the versioned Root context binds
`accessGroup`, construction and geometry. It MUST NOT be reused across sites
or publisher security namespaces. It never crosses the publisher trust
boundary and is never a delivered, encryption, MAC, signing or envelope key.
A key service that starts from a wider master secret derives each
publisher-scoped `keyDerivationSecret` independently before this construction
profile; the tenant or namespace used for that derivation is key-service
configuration, never a wire coordinate. Issuer identity, delivery origin,
publisher signing-key identity and render identity do not enter any context.

The only purposes selected here are Root, Step and Leaf: Root consumes this
secret, while Step and Leaf consume chain state under their distinct contexts.
No standalone base exact-key derivation is selected. A future construction
profile that defines another purpose MUST specify a distinct versioned,
unambiguous KDF context. Every registered purpose shares its derivation
secret's lifecycle: rotation, retirement, or deletion affects all of them. A
publisher whose purpose cannot accept that coupling uses a separate site-local
derivation secret.

<a id="primitive"></a>
### 6.3. Primitive

Every derivation is one HKDF-SHA-256 invocation (RFC 5869) with an empty salt.
Root and Step produce exactly 16 octets of chain state. Leaf produces the
16-octet exact leaf that
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements)
defines. The two output widths coincide:

```text
HKDF(ikm, info, width) = HKDF-Expand(HKDF-Extract(salt = "", ikm), info, width)
```

An empty salt and a salt of 32 zero octets give the same output under
HMAC-SHA-256; a library that substitutes `HashLen` zero octets for an absent
salt conforms.

<a id="context-encoding"></a>
### 6.4. Context encoding

Contexts are binary. Integers are unsigned big-endian of fixed width. Strings
are length-prefixed by their encoded byte length. No delimiter, no JSON, no
text form is authoritative.

```text
u8   domain          0x01 root, 0x02 step, 0x03 leaf
str  constructionId  u16 length || UTF-8 "dca-period-chain-v1"
str  accessGroup     u16 length || UTF-8 octets
u16  chainsPerDay
u16  periodMinutes
u32  windowStart     minutes since epoch
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
position encoding. With the 19-octet `dca-period-chain-v1` identifier, every
context is 34 octets plus the access-group length; a seven-octet access group
gives a 41-octet context. The root context names the terminal position so that
"root state is `S[N-1]`" is fixed by octets, not by prose.

<a id="derivations"></a>
### 6.5. Derivations

```text
Root:  S[N-1] = HKDF(keyDerivationSecret, ROOT_INFO(family, geometry, w), stateWidth)
Step:  S[i]   = HKDF(S[i+1],             STEP_INFO(family, geometry, w, i), stateWidth)
Leaf:  P[i]   = HKDF(S[i],               LEAF_INFO(family, geometry, w, i), leafWidth)
```

The `i` in `STEP_INFO` names the output state `S[i]`; its input is `S[i+1]`.
Each state is therefore bound to its own coordinate and cannot be replayed at
another position. The
root context carries the complete geometry and the window start, so two
geometries with the same terminal label and period length produce unrelated
state, and adjacent windows are independently rooted. The domain byte and fixed
construction identifier separate root, step, and leaf from each other and from
other constructions.

<a id="operations"></a>
### 6.6. Operations

- **Root derivation.** Derive the terminal/root state `S[N-1]` for a window.
- **Backward step.** From `S[j]` derive `S[i]` for `i < j` in the same window by
  applying Step for `j-1, j-2, …, i`. Forward derivation is infeasible because
  it inverts HMAC-SHA-256, and another window's state needs the key-derivation secret.
  An implementation refuses such a request as a usability guard; the boundary
  itself comes from the transcript.
- **Exact leaf.** From `S[i]` derive `P[i]`.
- **Expansion.** From `S[j]` derive `P[j], P[j-1], …, P[0]` in one backward
  walk, deriving each leaf from the state retained at that position. See
  [Bounds](#bounds). A whole-window walk is the special case `j = N - 1`;
  expansion from a lower cutoff covers only that cutoff through position zero.
- **Cutoff.** A cutoff is `S[i]` together with its coordinate; it carries no
  separate representation. On the wire the 16 state octets travel in canonical
  base64url (22 characters) as a collection member whose
  name is `label(w, i)`.

<a id="deterministic-regeneration"></a>
### 6.7. Deterministic regeneration

`keyDerivationSecret` is publisher-held retained derivation input. It never crosses the
publisher trust boundary. A window's terminal state is derived
deterministically from that secret and the complete window context. The
publisher therefore retains or replicates the key-derivation secret and profile
configuration, not every window state or exact period leaf. It can regenerate
the terminal state, walk to a requested position, and reproduce the identical
canonical `periodKey[t]` when preparing a render or issuer capability. This
provides:

- no per-period or per-window state-storage requirement at the publisher;
- deterministic recovery and multi-node publisher operation from shared
  retained input and profile configuration;
- an explicit maximum derivation span of `N` chain positions;
- independently derived state for adjacent windows; and
- period and window labels that are straightforward to reproduce and debug.

Publisher implementations may cache derived exact leaves across renders. Reuse
is scoped to the same derivation secret, construction version, geometry, access
group, and coordinate. Such a cache is an optional optimization, disposable
because the retained derivation secret and configuration regenerate its
contents; the protocol does not require persistent chain-state storage.

Every producer that regenerates a canonical leaf and wraps under it is bound by
the nonce and invocation discipline of
[spec--period-keys.md](spec--period-keys.md#content-wrapping-and-rollover),
whose counting domain spans all of them.

Deleting or rotating the key-derivation secret deliberately ends regeneration
for dependent family generations unless the old retained input is retained
under an explicit lifecycle policy. The publisher manages this as
`keyDerivationSecret` lifecycle, rather than routine chain-state retention.

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

The client follows coordinates embedded in article key candidates. It does not
use its own wall clock to decide which key is authorized.

<a id="windows"></a>
### 7.2. Windows

A chain window is a deterministic half-open interval `[start, end)`. Every
window has an independently derived terminal/root state from the publisher's
key-derivation secret and complete window context. A positioned key inside one window
has no value for `start - 1` and cannot derive into the next window.

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

A reference setting is `2/15`: two
twelve-hour windows per day and 48 leaves per chain. It is informative only.
The prototype's `2/60` is likewise not a default. There is no protocol
default; every chain-bearing message resolves explicit geometry for every
chain-bearing family, and one supplied capability is valid input without a
second label to reveal spacing.

Windows are anchored at UTC midnight. Window `k` of a day starts at
`k × windowMinutes` minutes after midnight, `0 ≤ k < chainsPerDay`. Position
`i` of a window starts `i × periodMinutes` minutes after the window start,
`0 ≤ i < N`. The terminal position is `N - 1`.

A chain-bearing message may carry one publisher-selected document-wide pair
and may carry a complete pair per access-group family. The resolution order is:

```text
access-group-family override
    ?? document-wide geometry
```

At least one of those scopes must supply geometry for every chain-bearing
family; a family for which neither exists is invalid. The document-wide value
and every family value are the complete pair; partial override or
field-by-field merging is forbidden. A per-key override is not defined. Family
values are keyed by `accessGroup`, not issuer, because all issuers opening one
canonical family must derive the same leaves.

A publisher generation using the canonical construction selects the geometry,
because it constructs the canonical chain and the article-wrapping leaves. An issuer may
choose a shorter authorized cutoff or
return exact leaves, but it cannot choose different geometry for the same
family: doing so would derive different key bytes from those used by the
article.

Each chain-bearing message has one effective geometry per access-group family.
An applicable malformed or unsupported override fails that family's chain
operation; it does not fall back to a lower-precedence value. The same family
cannot select different geometry for different issuers in one message.

Inheritance from the document scope compresses the wire only. It is not ambient
state. An actor that repackages a chain capability into another message
preserves its resolved geometry. An issuer response carries the resolved pair
for every family it returns. Old and new messages may coexist in a client cache
under their respective resolved geometry.

The resolved pair is part of the KDF context and of the chain envelope BIND.
Exact-only actors do not derive from it. Raw JSON spelling, member order, and
whether the pair came from document or family scope do not change derived
bytes. An issuer or client must not infer geometry from labels, entry count, or
their spacing.

The first protocol version permits only one effective geometry for a family
generation in one message. If a future migration must carry two geometries for
the same logical family in one current/next collection, it needs independently
identifiable subcollections rather than per-key inheritance exceptions.

All exact leaves, chain states, and article wraps for one chain-bearing family
generation inside one message are derived under one derivation secret,
canonical construction, and resolved geometry. Different generations coexist
only across messages and as retained client candidates at an applicable lookup
coordinate.

Under every permitted geometry, one configured period is one chain position,
and a render time does not start a new rolling chain. The same label
deterministically maps to one window and position for the whole generation.
This profile assigns each coordinate to one stationary chain window.
Independently rooted overlapping linear windows would produce different leaves
for the same coordinate. Other constructions can support rolling grant
intervals; they are outside this profile.

Window length is a security and interoperability boundary, not merely a local
loop bound. It is independently rooted through the window start in the root
context and unambiguously identified through the resolved pair and the label.

<a id="coordinate-labels"></a>
### 7.3. Coordinate labels

A chain-bearing family labels every coordinate on the wire as:

```text
YYMMDDTHHMM     UTC, fixed eleven characters
```

`YY` is the year within 2000 to 2099, the first `MM` is `01` to `12`, `DD` is
the day within that month, `HH` is `00` to `23`, and the final `MM` is `00` to
`59`. These field ranges, the real-calendar test, and the family-grid test are
normative. The endpoints `000101T0000` and `991231T2359` describe the overall
supported interval; lexical inclusion between them is not sufficient
validation. A label is on the family grid when its minute of day is a multiple
of `periodMinutes`. A chain-bearing family labels an hourly period
`251023T1400`, never `251023T14`. The nine-character base spelling and the fixed
form stay distinct coordinates, as the base requirements state.

The mapping between a label and the construction coordinate is:

```text
M           = minutes since 1970-01-01T00:00Z of the labeled instant
windowStart = M - (M mod windowMinutes)
position    = (M - windowStart) / periodMinutes
label(w, i) = format(w + i × periodMinutes)
```

`format` spells the labeled instant as `YYMMDDTHHMM`, each field zero-padded
to its width; it is the inverse of the mapping above. `windowStart` is the
window identity in the root context. Because `windowMinutes` divides 1440 and
the epoch begins at UTC midnight, this is the same window as the
midnight-anchored definition above.

Exact-only issuers and clients treat admitted `t` as opaque bookkeeping, as the
base requirements state, and the base grammar admits eleven-character labels.
Using the canonical construction therefore changes no exact-only issuer or
client role; an issuer selected for chain input applies the stricter admission in
[Request member](#request-member). The publisher's label formatter emits the
fixed form for every chain-bearing family, where the base formatter spells
hourly periods in nine characters. An exact leaf wrapped for a chain-bearing
family carries this label in its base `dca-bind-v1` period binding and in its
content-wrap entry. Exact-period content-key wrapping uses the empty AAD defined
by the content-protection specification.

The two-digit year bounds this profile's canonical construction at
2099-12-31. A deployment MUST select a successor period-chain profile with a
wider label before it emits a later coordinate.

<a id="chain-supply-and-window-rollover"></a>
## 8. Chain supply and window rollover

[spec--period-keys.md](spec--period-keys.md#content-wrapping-and-rollover) specifies
content-key wrapping, the nonce and invocation discipline of exact leaves, and
the three independent coordinate sets. This section adds what chain supply
changes across a window boundary.

The analogous current/next chain supply contains terminal state for two
independently rooted stationary windows. Under the `2/15` example those windows
together span 24 consecutive hours aligned to chain-window boundaries, but they
do not promise 24 future hours from the render instant or necessarily coincide
with one UTC calendar day. Geometry describes derivation layout; it does not
select an issuer grant duration or authorize the client for an entire window.

Inside one chain window, a client retaining a later chain position can derive
an earlier article leaf. A later exact leaf cannot do that. At an independently
rooted window boundary, later-window state cannot derive an old-window leaf.
Equivalent no-round-trip behavior then requires retained old state, another
unlock, or article wraps under both windows.

Under the `2/15` reference geometry, numbering positions across the day for
readability while the construction indexes `0` to `N-1` inside each window, an
article may have one wrap under `P72` while its issuer carrier contains `S95`
for window `[48,96)`, or exact leaves `P72` through `P76`. Returning `P72` through `P76` prepares
the client to open later matching articles; it does not require five wraps on
the current item.

Supplying terminal state for the next independent window grants the issuer that
next-window ceiling early. It may be appropriate for rollover, but is an
authority decision rather than a free consequence of overlap authoring.

<a id="period-chain-role-requirements"></a>
## 9. Period-chain role requirements

Base exact-period duties are normative in
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements). The
duties below belong to the optional period-chain profile, which depends on the
exact-period profile. A role is bound only by the period-chain duties it claims
or that trusted deployment configuration selects for a complete route.

The following tree is an informative map. The requirement list after it is
normative.

```text
Exact-period dependency
└── Exact periodKey capability and role requirements (spec--period-keys.md)

Period-chain profile (dca-period-chain-v1)
├── Canonical chain construction and window geometry
├── Canonical periodKey leaf derivation
├── Derivable periodChainKey capability
└── Extension carrier, BIND and relay

Role requirements
├── Publisher:
│   ├── MAY use the canonical construction for a family generation
│   └── MAY supply exact members, chain members or both per issuer route
├── Request path:
│   └── selected relay MUST carry chain material unchanged
├── Issuer:
│   ├── selected chain input MUST admit and process periodChainKey supply
│   └── MAY project exact leaves or return authorized chain state
└── Client:
    └── selected chain response MUST admit and derive periodChainKey grants
```

The publisher may use the canonical construction for a family generation.
That private choice fixes the generation's ancestry but does not by itself
select a cross-role period-chain path. Publisher chain supply, issuer chain
input, request relay, issuer chain output and client derivation are distinct
duties. Exact keys remain the dependency interoperability surface.

The role requirements are:

- A publisher generation that uses this canonical construction **MUST** derive
  every shared exact leaf for that generation through it.
- For each issuer route, the publisher **MAY** supply exact members, chain
  members or both. Exact-only supply is an exact-period path. Supplying chain
  members selects a period-chain supply duty for that route.
- Before a publisher emits chain-only period supply for a route the deployment
  relies on, trusted configuration **MUST** establish request relay and issuer
  chain-input support. An independently authored direct content-key route is a
  separate complete alternative and is not forced through the chain path.
- A request path selected for relay **MUST** carry the applicable extension
  members unchanged and **MUST NOT** treat relay support as authorization.
- An issuer selected for chain input **MUST** admit and process chain supply
  under this specification. It **MAY** project authorized exact grants.
- An issuer **MAY** return a chain grant only when every derivable coordinate
  from the window start through its cutoff is authorized and the route's
  trusted configuration establishes that its clients accept and derive that
  response over the selected transport.
- A client selected for chain response **MUST** admit the response and either
  retain positioned state for bounded derivation or expand selected exact
  leaves under [Client retention strategy](#client-retention-strategy).

Support or field presence alone does not force chain use. Exact plus chain
supply authors two available forms; the route's selected duties and policy
decide which valid source contributes to an operation. An issuer that consumes
chain input may end the optional path by returning ordinary exact leaves.
Returning positioned chain state selects the additional issuer-output,
transport and client-derivation duties.

A family generation that used the canonical construction stays compatible
with later chain delegation over its existing article wraps. A generation
that did not use it acquires no such ancestry later.

<a id="capability-and-configuration-model"></a>
## 10. Capability and configuration model

There is no deployment-wide `chainMode`. This version defines no request or
signed-assertion member that offers, discovers or negotiates client
chain-response support. A document or response can disclose that its producer
selected a chain representation, but that does not establish what the client
accepts. Each fact below is trusted deployment configuration, scoped to one
publisher-to-issuer route and the client population that route serves. A
**route** is that configured publisher-to-issuer path together with the request
path and client population assigned to it.

1. Publisher supply. The publisher enables the canonical construction for
   named family generations and configures whether
   each issuer route receives exact members, chain members or both.
2. Issuer input. The issuer enables or disables chain input for the route.
3. Issuer output. The issuer enables, independently of input, whether the
   route may answer with projected exact leaves, with direct chain state, or
   with either.
4. Request relay. The request path has selected the relay capability.
5. Client derivation. The client population the route serves is enabled to
   accept and derive chain state.
6. Transport. The selected transport can safely deliver the response form.

These facts are independent, and none is entitlement. An issuer can accept
chain input and return exact leaves to a non-deriving client. A client can
relay without deriving. A route may return chain state only when trusted
configuration establishes facts 3, 5 and 6 for it. Relaying the extension
members, the presence of `periodChain` in a request, and successful opening of
a chain envelope establish nothing about client chain-response support. They
select or authenticate source coordinates, not the client's ability to consume
chain state, under the issuer-decision invariant of
[spec--security-model.md](spec--security-model.md).

When route configuration does not establish chain response support, the issuer
projects authorized exact leaves. When exact output is not selected for the
route or is not sourceable from the supplied members, the issuer returns no
reusable period capability instead of improvising a representation. An endpoint
that serves clients of different capabilities returns exact leaves unless an
authenticated or otherwise trusted route distinction selects a chain-capable
population. Defining such a distinction is deployment work; this version adds
no wire mechanism for it.

Out-of-band trusted route configuration is this version's selection signal for
the response representation. How a deployment records these facts, onboards a
publisher or ships its configuration is outside this specification. Automated
discovery may be defined later. It must authenticate the facts it supplies,
cannot widen authorization, and is not a condition of promoting this
extension.

A **cryptographic capability** is key material whose bytes confer the authority
defined by [Key and capability model](#key-and-capability-model).
**Implementation support** says which protocol operations an actor can perform.
**Configuration** chooses which supported operations may be used for a
publisher-to-issuer relationship. **Negotiation** means one peer offers and
another selects a response representation within one exchange. This version
defines no such chain negotiation; representation follows route configuration.
None of those terms is a synonym for entitlement.

A **canonical construction** is the versioned derivation and byte transcript
fixed by a profile; it is not a second profile kind. The period-chain profile
`dca-period-chain-v1` fixes this version's chain construction and depends on
the **exact-period profile**, `dca-v1-exact-period`. Exact-period fixes one
16-octet leaf and AES-128-GCM exact wrap, and the chain construction produces
that same leaf capability;
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements)
defines its meaning. Route configuration chooses capability support, not width.
[spec--profiles.md](spec--profiles.md) defines the profile dependency and the
complete composition of role and mechanism requirements.
A configuration toggle is not a profile.

Configured capability is never entitlement. The issuer first decides the
authorized coordinates and then chooses an accepted response whose complete
cryptographic reach is contained in that decision.

In the reference implementation, publisher family and window supply is
configured in
`js/v1/extensions/period-chain/core-publisher/periodFamilySupply.js`, while
per-issuer exact/chain delivery is configured by
`js/v1/core-publisher/issuerSupplyPlan.js`. Issuer input is enabled by composing
`js/v1/extensions/period-chain/core-issuer/periodChainIssuerEngine.js`; carrier
presence then selects the presented families. That engine's `representation`
option selects exact or chain output. Request relay is the injected
`js/v1/extensions/period-chain/core-client/PeriodChainRequestBuilder.js`. Client
chain consumption requires
`chainCache` and an admitted `periodChainProfile`; direct raw retention also
depends on `acceptDirectFallback` and `persistRawPeriodKeys`. Chain output is
limited to direct transport. No reference path selects the response form from
the request. Relayed geometry is input interpretation authenticated by chain
BIND, not capability selection. One processor holds one engine with a fixed
representation, so mixed client populations use separately composed
endpoints.

<a id="publisher-to-issuer-supply"></a>
## 11. Publisher-to-issuer supply

The publisher supplies typed capability members. The
issuer's supplied ceiling is the union of the reach of its valid members:

```text
issuer capability collection
├── periodChainKey[71]  -> exact leaves 48 through 71
└── periodKey[80]       -> exact leaf 80 only
```

This example intentionally withholds positions 72 through 79. It is one
composite ceiling, not two fallback routes. Exact and chain members may
therefore coexist for ordinary authority modelling, not only migration.

The publisher supplies the capability members in outer typed maps. In this
profile, each issuer-targeted encrypted chain carrier contains exactly one
positioned state; it binds that state and its full coordinate/geometry context.
A multi-entry encrypted carrier would need separate specification and is not a
selectable packaging choice here.

<a id="exact-supply"></a>
### 11.1. Exact supply

This subsection describes exact members inside a chain-capable issuer's
collection;
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements)
states the exact supply duty itself. The publisher includes selected exact
`periodKey` leaves as exact members of the issuer's protected capability
collection; for a family generation using the canonical construction these are
canonical leaves derived from its chains.

This form provides:

- exact or sparse issuer authority;
- no ability for the issuer to derive omitted periods;
- a low-complexity issuer tier; and
- straightforward exact processing and conformance tests.

Its irreducible cost is one key value plus coordinate metadata per supplied
access-group/period coordinate.

<a id="chain-supply"></a>
### 11.2. Chain supply

The publisher includes one positioned `periodChainKey` member for each
supplied window of an access-group family. The supplied position is normally
the window's terminal/root state; a lower position attenuates the issuer's
ceiling to the window start through that position.

This form provides:

- compact publisher-to-issuer supply;
- fine-grained exact projection by issuer policy;
- compact grants covering the window start through an authorized cutoff; and
- flexibility to vary grant duration without resealing every exact period.

Its reach is every coordinate from the window start through the supplied
position, and it needs chain-profile implementation at the issuer. It reaches
the issuer only through a request path that selected the relay capability.

<a id="collection-construction"></a>
### 11.3. Collection construction

An exact-only issuer receives only exact members. A chain-capable issuer may
receive chain members, exact members, or both according to the intended
publisher-supplied ceiling. Supplying exact members is not required merely
because the eventual client consumes exact output; a chain-input issuer can
project that output.

The issuer validates each member independently and computes authority from the
union of valid, selected members. A sealed member that fails invalidates that
member. A malformed or conflicting family collection, including
two positions from one window, invalidates that family's chain collection. A
malformed document-level `periodChain` geometry invalidates every chain
collection that depends on it;
an applicable malformed family override invalidates that family without
falling back to document geometry. Independently selected exact members remain
independent valid authority. They are usable after a chain failure only when
the request and issuer policy selected them as part of the intended union. The
issuer never reinterprets a failed chain member as an exact member, and it
does not silently select an exact fallback route.

<a id="extension-carrier-and-client-relay"></a>
## 12. Extension carrier and client relay

Publisher-to-issuer chain supply travels through the client request path as
two known extension members: the `periodChain` geometry object and the
`sealed.periodChainKeys` capability collection. The base request path carries
neither. A client selects the relay capability to carry them; relay is
transport support and does not make the client a chain deriver.

<a id="document-member"></a>
### 12.1. Document member

A chain-bearing document carries one top-level `periodChain` context object and
keeps each issuer's chain-key collection in the existing
`sealed.periodChainKeys` location:

```json
{
    "periodChain": {
        "chainsPerDay": 2,
        "periodMinutes": 15,
        "accessGroups": {
            "locked-data": { "chainsPerDay": 4, "periodMinutes": 5 }
        }
    },
    "issuerData": {
        "<issuerName>": {
            "sealed": {
                "contentKeys": { },
                "periodKeys": { },
                "periodChainKeys": {
                    "<accessGroup>": {
                        "<suppliedT>": "<sealed chain-state bytes>"
                    }
                }
            },
            "unlockUrl": "https://api.example.com/unlock",
            "keyId": "2025-10"
        }
    }
}
```

The document-wide pair and every entry in `accessGroups` are complete pairs; a
family entry replaces both document values.
The document-wide pair may be absent when every family in any issuer's
`sealed.periodChainKeys` has its own entry. A family present in
`sealed.periodChainKeys` without a
resolvable complete pair is invalid, and an applicable malformed entry fails
that family rather than falling back to the document pair. `suppliedT` is the
label of the supplied position, normally the window terminal. Each sealed value
is the 16-octet chain state at that position under `dca-period-chain-v1`,
sealed to the issuer under the chain
envelope BIND below and spelled in the canonical unpadded base64url of
[spec--data-format.md](spec--data-format.md), as is every chain member in the
request and the response.

<a id="chain-envelope-bind"></a>
### 12.2. Chain envelope BIND

The `pc` kind under `dca-bind-v1` is the chain-envelope binding. It carries
the resolved geometry; base `c` and `p` binding bytes are unchanged.

```text
dca-bind-v1 | pc | renderId | accessGroup | suppliedT
            | chainsPerDay | periodMinutes
```

The line break and spaces in this display are not part of the value. Fields
are joined with `|`, and `|` is forbidden inside every field, as in the base
grammar. `renderId` is the base64url render identifier, 22 characters for the
16-octet identifier of
[spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md). `suppliedT` is
the label of the supplied position. The two integers are decimal without
leading zeros; the production is `[1-9][0-9]*` with no sign or whitespace. The
publisher refuses to seal a `pc` binding that lacks either integer, and the
issuer refuses to open it; there is no shorter `pc` form. The sealed payload is
exactly 16 octets of chain state and nothing else. The BIND value is at most 124
octets at the 64-octet access-group ceiling; with the 16-octet payload it fits
the 190-octet plaintext capacity of RSA-OAEP at its 2048-bit floor with fifty
octets to spare. The ECDH
carrier is exactly 109 octets;
[spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope)
specifies that length and the refusal of a payload or envelope of another width. The
BIND value is the associated data of the seal, applied exactly as the base
sealing applies its BIND: AES-GCM additional data for the ECDH carrier,
authenticated plaintext prefix for the RSA-OAEP carrier. Window identity and
position are authenticated through `suppliedT` under the authenticated
geometry; geometry is authenticated as public context. The configured
period-chain profile fixes how the opened state is interpreted; the `pc`
envelope does not select that profile. Render identity ties the envelope to
the render whose evidence the issuer verifies. Nothing about the chain is
hidden inside the payload beyond the state bytes.

The envelope authenticates no publisher identity, and `renderId` is a value
the requesting publisher chooses in its own signed evidence. Publisher
separation therefore rests entirely on the registration-scoped opening key of
[spec--security-model.md](spec--security-model.md): the issuer resolves
`issuerName` and `keyId` only inside the registration whose key verified the
token, and mutually untrusted publishers hold cryptographically separate
opening keysets. A copied envelope opened under a shared keyset yields a
window ceiling of up to `N` leaves, not one coordinate, so a family that
selects this profile is served only by a registration whose opening keyset is
not shared with a publisher it does not trust. The envelope is render-scoped
supply and is sealed once per render; the capability it yields to a client is
not render-bound.

<a id="request-member"></a>
### 12.3. Request member

A relay client selects `sealed.periodChainKeys` members for the access groups
required by the request, using the same unresolved-item and access-group
selection boundary as the exact request path. It copies each selected label and
sealed value unchanged and carries the top-level `periodChain` object with
the geometry needed to resolve those families. It does not derive,
merge, or rewrite sealed members. Unselected family entries and overrides may
be omitted. Public routing or item selectors stay outside the carrier and
remain untrusted inputs to issuer processing.

A client that has not selected chain relay emits neither member. An issuer that
has not selected chain input treats both as unknown request members and ignores them. An
otherwise usable exact request proceeds exact-only. If ignoring them leaves no
recognized coordinate, the core protocol rejects the request as empty. In
either case chain-only supply yields no capability.

An issuer selected for chain input validates the request's `periodChain`
before opening any envelope: complete pairs, divisibility, and
`N` within [Bounds](#bounds). It then opens each member under the BIND built
from the resolved context and the member's label. A member whose BIND does not
verify, whose label is off its family's grid, or whose family lacks a resolved
pair fails as a chain member, and the issuer never reinterprets it as exact
supply.

<a id="capability-collection"></a>
### 12.4. Capability collection

The sealed collection is the outer typed map of capabilities. A chain member
is one positioned state/envelope for one window of an access-group family
generation. One issuer may receive several such members from different windows
of that family, up to `maxChainMembersPerFamily`; the per-family maximum counts
those window entries. Two members at the same window in one message are
invalid. Exact members live in `sealed.periodKeys` under the base grammar and
combine with chain members as one ceiling; see
[Publisher-to-issuer supply](#publisher-to-issuer-supply).

<a id="issuer-decision-and-response"></a>
## 13. Issuer decision and response

A compact issuer flow is:

```text
identify the configured publisher-to-issuer relationship and extension
    -> verify publisher evidence and the request boundary
    -> resolve and validate the explicit chain context, if the request
       carries the extension member and the issuer has selected it
    -> decide policy authority without trusting client-carried selectors
    -> open each selected chain envelope under its BIND
    -> intersect valid sourceable supply with the policy-authorized reach
    -> select an accepted response within that reach
    -> apply the required transport
    -> return an identifiable response
```

Opening an envelope authenticates its access group, geometry and supplied
position against the resolved context. Successful opening supplies
sourceable key authority, not entitlement. The issuer must not treat an opened
client-carried entry as a policy grant.

An issuer configuration may assign a publisher relationship or family to a
chain-owned period route. On that route, absent, invalid or unrepresentable
chain input does not silently select the base exact route. On that route, the
issuer maps its trusted policy result from its current coordinate as specified
below. Selection semantics for a separately configured base exact route are
outside this chain-route subsection. An untrusted request can remove either
carrier, so changing routes on absence would let the request choose which
selection rule interprets the same policy answer. Exact input remains available
through a separately configured base route, and a valid chain route may project
its selected reach into ordinary exact leaves. A deployment that deliberately
selects an exact-and-chain union must define that union before opening either
representation; a failed or removed member does not select it.

<a id="chain-route-periodcount"></a>
### 13.1. Chain-route `periodCount`

For a selected chain route, the issuer's trusted policy result supplies
`periodCount`, a non-negative integer; the client cannot set it. It is not a
request or response member. It names the maximum number of consecutive period
coordinates to select, beginning with the issuer-captured current coordinate.
A value of zero selects no period capability. The issuer aligns that first
coordinate by rounding its captured instant down to whole minutes and then
down to the family's period grid; a client clock grants nothing.

The issuer MUST limit the selection to coordinates reachable from valid
publisher-supplied members and to the response bounds in this specification. A
gap at the current coordinate or between consecutive coordinates stops the
selection. A count extending beyond supplied reach or a response bound is
clamped and is not, by itself, an error. The issuer MUST NOT manufacture
authority in another window or from an absent member.

`periodCount` selects the present-and-future delivery horizon; it does not
narrow a returned cutoff's inherent window-start-to-cutoff reach. For exact
projection, the selected coordinates are the exact leaves returned.

By selecting chain representation, the deployment authorizes delivery of every
coordinate from the window start through the cutoff. The issuer MUST enable
that representation only when this broader reach matches its intended policy;
the route's configured client capability is necessary for representation
selection, but alone is not authorization. No additional list of earlier
coordinates is required. If that reach is unacceptable, the route returns
authorized exact leaves or fails according to its selected response
capabilities.

A policy adapter MAY convert a duration into `periodCount` before invoking this
route. Duration units, rounding, and whether a partial current period counts
toward an advertised duration are issuer policy and are not DCA wire or chain
configuration.

Possible response forms are:

- direct item-specific `contentKey`;
- selected exact `periodKey` leaves; and
- positioned `periodChainKey` when every coordinate from the window start
  through its cutoff is authorized.

The issuer makes these grant choices per item or per family.
One response may, under explicit grammar, return a direct `contentKey` for one
item, exact `periodKey` values for another family, and a compact chain grant for
another. A forward exact-key horizon is a set of individually authorized
coordinates. Implementers must not confuse it with the chain key's
window-start-through-cutoff range.

A chain grant keeps raw states in the existing `keys.periodChainKeys` location.
Its resolved geometry travels in the top-level `periodChain` member of the
issuer-core result defined in
[spec--core-protocol.md](spec--core-protocol.md#7-baseline-issuer-core-result),
which the selected response binding preserves. In a mixed direct, exact, and
chain response the enclosing shape is:

```json
{
    "keys": {
        "contentKeys": { "<contentName>": "<base64url(content key)>" },
        "periodKeys": {
            "<accessGroup>": { "<t>": "<base64url(exact period key)>" }
        },
        "periodChainKeys": {
            "<accessGroup>": {
                "<cutoffT>": "<base64url(chain-state bytes)>"
            }
        }
    },
    "periodChain": {
        "chainsPerDay": 2,
        "periodMinutes": 15,
        "accessGroups": {
            "<overriddenAccessGroup>": {
                "chainsPerDay": 4,
                "periodMinutes": 5
            }
        }
    }
}
```

The response never inherits geometry from the request: `periodChain` resolves a
complete pair for every returned family using the same whole-pair override rule
as the document. A returned family with no resolvable complete pair is invalid.
The issuer emits `periodChain` and `keys.periodChainKeys` only when it has
selected chain response and has at least one chain grant to return.

`<cutoffT>` above is an ordinary canonical period coordinate `t`: the member
name under which the returned state is filed. It is not a separate request or
response field and it is not a coordinate supplied by the client. "Cutoff"
describes the authority of the issuer-selected returned `t` under the resolved
chain geometry. The request instead presents publisher-supplied state at
`suppliedT`, and chain-envelope `pc` BIND authenticates that `suppliedT`.
Neither the selected response `t` nor the cutoff concept enters base exact-key
`p` BIND; an exact period-key envelope always binds its own exact `t`.

Exact leaves returned for a chain-bearing family are ordinary base
`periodKeys` material. The client files them under the base exact-cache rule
and needs no chain context to use them. `maxRivalExactCandidates` in
[Bounds](#bounds) covers only exact leaves a client expanded from chain state
into a chain partition.

As normal chain-capability execution, a chain-input issuer may answer with
derived exact leaves. Route configuration records what those clients accept;
it does not require the issuer to return the broadest
representation those clients accept.

Direct versus client-bound delivery is a separate axis. The client-bound
mechanism exposes a non-extractable AES handle suited to exact use, not raw
derivation-capable state. Under this profile a chain grant is direct-transport
only.

<a id="client-retention-strategy"></a>
### 13.2. Client retention strategy

A chain-capable client may retain positioned chain state and derive exact leaves
lazily, or expand selected leaves eagerly and discard the chain state. These are
storage strategies over the same granted authority:

- retaining chain state preserves compact local regeneration for old matching
  renders but requires a chain-aware resolver and protected derivation state;
- expanding exact leaves reuses the simple exact cache but consumes more
  entries, and an evicted leaf cannot be regenerated after its source chain
  state is discarded.

This profile mandates neither strategy. [Bounds](#bounds) limits derivation
work and cache growth under both, and a client that has discarded both the
needed leaf and its derivation state reopens that render only through another
unlock.

<a id="capability-combinations"></a>
## 14. Capability combinations

| Issuer supply | Request path | Client response support | Result |
| --- | --- | --- | --- |
| Exact collection | Exact-only | Exact | Issuer returns authorized available leaves |
| Exact collection | Exact-only | Chain-capable | Issuer still returns exact; exact supply cannot reconstruct chain state |
| Chain collection | Exact-only | Any | Carrier never reaches the issuer; no supply unless an exact route is also configured |
| Chain collection | Chain relay | Exact | Issuer projects and returns authorized exact leaves |
| Chain collection | Chain relay | Chain-capable | Issuer may return exact or an authorized cutoff state |
| Exact and chain collection | Chain relay | Any | Issuer grants from the authorized union of sourceable member reach |

A request path that has not selected chain relay remains a conforming
exact-period path. It cannot carry chain-only issuer supply, so a publisher
that supplies such an issuer only chain members must also give it an exact
route or accept that clients without chain relay cannot reach it. Selecting
relay does not imply that the client accepts chain responses. The client
response support column is fact 5
of [Capability and configuration model](#capability-and-configuration-model),
a configured route fact; an endpoint serving clients of mixed capability
without a trusted route distinction is configured as Exact.
Every row additionally requires the issuer-output and transport facts for its
stated result; the three displayed columns do not replace those requirements.

One shared render may give issuer A exact supply and issuer B chain supply for
the same canonical leaf family. Both can return identical exact leaf bytes.

<a id="compatibility-boundary"></a>
## 15. Compatibility boundary

[spec--period-keys.md](spec--period-keys.md#compatibility-boundary) states the
exact-key adaptation seam. Chain support cannot add derivation ancestry to
independently generated leaves: that change starts a new generation and newly
wrapped content. A generation that already used this canonical construction
privately may later expose chain supply over its existing wraps; the prior
exact-only path did not itself select the cross-role profile. Chain processing
is optional for issuers and clients, so an exact-only issuer or client conforms
fully to its role. A system without a compact chain capability can still be
served by a chain-holding DCA issuer, which derives and returns exact leaves.

<a id="worked-examples"></a>
## 16. Worked examples

This section is informative. The examples use the `2/15` reference geometry and
day-absolute positions: `P72` is the exact leaf at position 72 of the day and
`S95` the chain state at position 95. The exact-period profile's exact-only path
is the first example of
[spec--period-keys.md](spec--period-keys.md#worked-examples).

<a id="chain-issuer-and-exact-client"></a>
### 16.1. Chain issuer and exact client

The publisher seals terminal chain state `S95` to issuer B for the 48-position
window `[48,96)`. The client has selected the relay capability and forwards that
issuer material without deriving from it. Issuer B authorizes coordinate 72,
derives `P72`, and returns that exact leaf. The client operates exactly as in
the exact example of
[spec--period-keys.md](spec--period-keys.md#exact-issuer-and-exact-client).

<a id="chain-issuer-and-chain-client"></a>
### 16.2. Chain issuer and chain client

Issuer B authorizes every coordinate from the window start through coordinate
72. The route's configuration establishes that its clients accept chain state
over the selected transport, so the issuer returns `S72`.
The client derives `P72` and earlier leaves as articles require them.

The response is valid only because policy authorized every derivable
coordinate, not merely because the route is configured for chain responses.

<a id="future-exact-grant-inside-a-window"></a>
### 16.3. Future exact grant inside a window

A subscription begins at coordinate 72 inside a window that began at 48. The
issuer can return `P72` in advance without granting 48 through 71. Returning
`S72` grants every coordinate from 48 through 72, so the route returns it only
when policy authorized that whole reach.

If an article rendered before the subscription start was already wrapped under
`P72`, the future leaf opens it immediately. A leaf opens whatever the publisher
wrapped at its coordinate, regardless of publication time.

<a id="independent-window-boundary"></a>
### 16.4. Independent window boundary

An article rendered at 11:50 is wrapped using window `[00:00,12:00)`. At
12:10 window `[12:00,24:00)` in the same generation is
active. A position from the new window cannot derive the old article leaf.
Local opening without another issuer interaction therefore requires retained
old state or an article candidate under the new window as well.

<a id="counts-and-efficiency"></a>
## 17. Counts and efficiency

This section is informative.

The exact-key size, cache, clock, and TTL numbers in this section are
illustrative. They are not protocol defaults.

Let:

- `I` be issuer count;
- `G` be access-group count;
- `P` be supplied exact periods; and
- `W` be touched chain windows.

Publisher-to-issuer capability-value counts are:

```text
exact key values: I × G × P
chain key values: I × G × W
```

For one twelve-hour window containing 144 five-minute periods, three access
groups, and two issuers:

```text
exact: 2 × 3 × 144 = 864 key values
chain: 2 × 3 × 1   =   6 key values
```

This is a key-material count per render, not an encrypted-carrier count or
measured byte benchmark; chain and exact envelopes alike bind `renderId` and
are sealed once per render. The selected chain carrier has one positioned state
per envelope, so this layout produces 864 versus six public-key envelopes. A
batched issuer-targeted carrier is not selected here and would require separate
specification. Key values, encrypted carriers and encoded bytes, including
labels, geometry metadata and response expansion, are separate measures.

Even where two exact and two chain objects happen to tie across a window
boundary, their supplied authority differs. Two exact keys expose two named
coordinates. Two terminal chain positions can let issuer policy select many
fine-grained coordinates across two windows.

<a id="multiple-access-groups-and-issuers"></a>
## 18. Multiple access groups and issuers

[spec--period-keys.md](spec--period-keys.md#multiple-access-groups-and-issuers)
states the exact rules. No role derives another group's keys from a chain
position.

Multiple issuers may receive different supply representations over the same
canonical generation:

- issuer A receives selected exact leaves;
- issuer B receives terminal chain state; and
- both can ultimately return the identical `periodKey[t]` needed by the article.

Issuer envelopes remain independently encrypted for each issuer. Canonical leaf
identity does not make issuer transport or custody shared.

<a id="generation-identity-and-migration"></a>
## 19. Generation identity and migration

For a chain-bearing article, the client resolves the article's geometry from its
`dca-data`. It first considers ordinary exact candidates under the base
cache boundary of
[spec--period-keys.md](spec--period-keys.md#generation-identity-and-migration).
It may additionally derive candidates only from the one chain partition selected
by that article's resolved geometry under the configured profile. It does not
search unrelated retained geometry partitions. Exact leaves returned by an
issuer, including leaves projected from chain supply, remain ordinary base exact
candidates; leaves expanded locally from retained chain state remain inside the
matching chain partition.

Chain caches follow the same candidate rule. A chain cache partitions by:

```text
publisher delivery origin
  × access-group family (with the configured issuer partition, if any)
  × period-chain profile and canonical construction (no identifier travels;
    the route's configuration for
    that family generation states it)
  × chainsPerDay
  × periodMinutes
```

The derivation secret is not a public partition selector in this profile.
Different derivation-secret bytes at one coordinate remain bounded rival candidates
inside the applicable partition.

Inside one partition it files candidates by window start and position and
retains rival bytes at one coordinate. It does not need to discover which
derivation secret is globally "active".

When two retained chain keys have the same coordinate, identical bytes are
duplicates and different bytes remain rival candidates. When they have
different positions in one window, the later key can be derived backward to
the earlier coordinate and compared there. Equality proves that the later key
subsumes the earlier one; inequality keeps both. A client cannot derive forward
beyond a cutoff, and no cleanup decision assumes that it can.

Without a generation selector, rollover can require deriving more than one
candidate leaf for a target `t`. The client caches those exact derived leaves
and then uses the ordinary exact-period candidate trial, newest filed
first. This bounded rare-path work is the reason this profile adds no generation
field to chain capabilities.

Adding chain support cannot retroactively make independently generated legacy
leaves derivable. A family that starts using the canonical construction starts
a new generation; its earlier ciphertext still needs its earlier keys. A
generation that already used the canonical construction privately may later
select chain supply over its existing wraps. Until then, its exact-only route
does not expose or operationally select the period-chain profile. Migration
from independently generated earlier material needs explicit candidates or a
retirement boundary.

The base hourly label `YYMMDDTHH` and this profile's fixed
`YYMMDDTHHMM` label are distinct opaque coordinates, even when both spell the
same wall-clock hour. A migration does not normalize or alias them. Old and new
coordinates and their acquisition routes coexist until the old publication is
retired.

<a id="keyderivationsecret-rollover"></a>
### 19.1. `keyDerivationSecret` rollover

Secret replacement starts new family generations inside the same logical
publisher/access-group families that depend on that derivation secret. It may
keep the same profile and geometry:

1. The publisher generates or provisions a replacement `keyDerivationSecret`.
2. Newly rendered items use canonical leaves and issuer capability collections
   from each new dependent family generation.
3. A client holding only old-generation material tries its cached candidates,
   misses, unlocks the new render once and files the returned exact or chain
   capability beside the existing candidates.
4. Old cached renders continue using old cached candidates, or unlock through
   their retained old issuer carrier while that material remains accepted.
5. Later acceptance retirement and key-derivation-secret deletion follow the separate
   lifecycle rules below.

Opening the new issuer carrier uses the issuer's opening key and verified
publisher evidence, not a client-held old `periodKey`. The new period
capability is the result of unlock, not a prerequisite for it.

Old and replacement generations may coexist while their material remains
usable. No derivation-secret or generation selector appears on the wire: where
rival candidates share a coordinate, the client retains the bounded candidates
and authenticated content-key unwrap selects the bytes matching that item.

Scheduled rollover may align with a new window to reduce same-coordinate
coexistence, but emergency mid-window rollover remains representable.

Changing `chainsPerDay` or `periodMinutes` starts a new family generation and
lands in a different cache partition through the resolved pair. Changing the
KDF transcript, geometry parameter rules, or context encoding requires a new
profile identifier and a different partition. Changing delivered-key width
requires a new suite/specification version; DCA v1 has only one width.
Receiving new geometry, a new profile, or a retained rival candidate is not a
deletion command because retained old renders may still require old material.

The protocol requirement is smooth generation rollover: new renders and
unlocks work under replacement material without a cache loop or dependency on
an old period key. Publisher incident procedures, including cache purges, are
outside this specification. This canonical construction does not promise
no-new-unlock behavior across a generation boundary. A client that has no
matching new-generation candidate unlocks the new render once; a publisher may
author overlapping alternatives as a deployment policy.

<a id="capability-lifecycle"></a>
## 20. Capability lifecycle

[spec--period-keys.md](spec--period-keys.md#capability-lifecycle) states the two
lifecycle actions common to every period key: retiring acceptance of published
issuer material, and the impossibility of retiring client-held authority. This
profile adds a third:

1. **Deleting a publisher derivation secret** stops the publisher
   from regenerating window states and leaves for every dependent family
   generation. It does not erase chain state already sealed into retained issuer
   carriers, and it does not revoke authority already sealed for an issuer or
   delivered to a client.

The passage of a window boundary does not expire key bytes, as the exact rule
for period boundaries states. Chain geometry alone is not a revocation deadline.

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

New exact-only renders do not retire old chain-only markup by themselves. The
deployment chooses the mechanism in step 2 that satisfies this profile's
obligation.

<a id="failure-and-downgrade-principles"></a>
## 21. Failure and downgrade principles

This section is an informative summary. Normative failure rules are in the
sections it cites.

These principles summarize failure rules stated in
[Collection construction](#collection-construction),
[Request member](#request-member),
[Issuer decision and response](#issuer-decision-and-response),
[Chain results and transport composition](spec--response-binding.md#51-chain-results-and-transport-composition)
and [Bounds](#bounds), and in the
core protocol and response-binding specifications for partial success and
origin checks; this section is informative.

- The issuer fails explicitly on an unsupported selected input capability.
- For an issuer selected for chain input, a malformed chain object is
  not treated as an absent optional field.
- The issuer does not process unrelated bytes as exact input when chain supply
  fails validation or opening.
- A separately supplied exact route remains usable only when selection rules
  identify it as an independent valid route.
- Client response preferences do not weaken issuer authentication, origin
  checks, authorization, or transport requirements.
- The issuer does not select a route or authorize an exact fallback, broader
  response, or raw response merely because a capability is omitted.
- Partial success across groups or items must be deliberately specified rather
  than inferred from parser behavior.
- Derivation work and returned-key counts require implementation limits.

<a id="bounds"></a>
## 22. Bounds

Every chain operation is bounded by the resolved geometry and by the fixed v1
protocol maxima below. A producer MUST stay at or below them. A consumer
that reaches period-chain admission applies the handling stated below; a
deployment MAY enforce a stricter finite resource cap and reject earlier, but
that local cap does not change whether the peer's chain message conforms to
this profile.

<a id="protocol-maxima"></a>
### 22.1. Protocol maxima

| Constant | Value | Bounds |
| --- | --- | --- |
| `maxPositionsPerWindow` | 288 | `N = (1440 / chainsPerDay) / periodMinutes` |
| `maxChainMembersPerFamily` | 2 | chain members for one access group in one chain collection in one message |
| `maxChainMembersPerMessage` | 16 | chain members across all access groups in one chain collection in one message |
| `maxExactLeavesPerFamily` | 288 | exact leaves one response returns for one access-group family |
| `maxExactLeavesPerResponse` | 512 | exact leaves across all families in one response |

The two exact-leaf rows are independent protocol constants. The family value
equals `maxPositionsPerWindow` in v1 but is not derived from it: it bounds
chain-projected response output, while the positions value bounds geometry.
The response value bounds total chain-projected expansion until the base
format defines its own response limits.

For chain-member limits, a producer MUST NOT emit more than two members for
one family or more than 16 across the chain collection of one message. A
consumer that receives more than `maxChainMembersPerFamily` treats that family
as invalid while independently admitted sibling families and core sections
remain usable. A consumer that receives more than
`maxChainMembersPerMessage` treats the whole chain collection as invalid; it
does not reinterpret any of those members as exact input. Independently
admitted core sections remain subject to their applicable focused specifications.

For exact projection, the issuer clamps a `periodCount` that exceeds either
exact-leaf maximum before response construction; the clamp is not an error. The
issuer MUST return no more than `maxExactLeavesPerFamily` for one chain-bearing family and
no more than `maxExactLeavesPerResponse` across the response. Projected leaves
are ordinary exact `periodKeys` with no chain-provenance marker, so a client
applies the exact-result admission of [spec--period-keys.md](spec--period-keys.md)
and MUST NOT infer a different client limit from their arrival on a route that
also selected chains. These two maxima constrain the chain-capable issuer's
selection and response construction, not the base exact wire shape.
A chain-bearing family that produces no capability after these clamps is
omitted under the core result rule in
[spec--core-protocol.md](spec--core-protocol.md#7-baseline-issuer-core-result);
the omission adds no wire error.

`N` is the number of positions in one window and the maximum length of one
backward walk. A producer MUST NOT emit chain geometry whose `N` exceeds
`maxPositionsPerWindow`. A consumer treats such geometry as invalid under the
family or message scope of the carrier that supplied it. `2/15` gives `N =
48`; `2/60` gives `N = 12`; `4/5` gives `N = 72`. Both one chain per day
with five-minute periods (`1/5`) and five chains per day with one-minute
periods (`5/1`) give `N = 288`.

Expansion of one chain member into exact leaves walks backward once from the
supplied or granted position to the window start and derives each leaf from
the retained state at that position. The cost is at most `N - 1` steps and `N`
leaf derivations, `2N - 1` HKDF invocations in total. Deriving every leaf by
repeating the walk from the cutoff is quadratic and is not a conforming
expansion algorithm.

Total issuer full-expansion work for one message is therefore at most
`maxChainMembersPerMessage × (2N - 1)` HKDF invocations: 9,200 at the v1
ceilings of 16 members and `N = 288`. The member maximum bounds carrier and
opening work even when exact-leaf output clamps or policy filtering cause the
issuer to return fewer leaves. A publisher starting from the key-derivation
secret spends one more invocation
per window for the root; an issuer starts from publisher-supplied state and
never receives that secret. A client that tries `Rchain` locally retained rival
chain candidates at one coordinate spends at most `Rchain × (2N - 1)` HKDF
invocations. That client lookup is lazy local work for one requested
coordinate, not the full-message issuer bound. An actor may cache intermediate
state or leaves to spend less; the bound assumes no cache.

Exact expansion returned to a client counts against `maxExactLeavesPerFamily`
and `maxExactLeavesPerResponse`. Deriving leaves for an exact response is
issuer work under the walk bound above.

<a id="local-retention-policy"></a>
### 22.2. Local retention policy

The profile does not fix `maxRivalChainCandidates` or
`maxRivalExactCandidates`. A host MUST keep finite bounds on both retained
rival sets and on the trials performed for one operation, but their numeric
values are local availability and resource policy. They do not affect wire
validity and differing values do not make two peers nonconforming.

Candidate trial stays inside one partition. The client resolves geometry from
the document it is opening for each chain-bearing family and searches only that
partition for an article wrap. `Rchain` is the host-local maximum chain rivals
it will retain and try for one operation; `Rexact` is the corresponding local
maximum for exact rivals. The worst uncached chain walk is
`Rchain × (2N - 1)` HKDF invocations. Exact rival leaves add at most `Rexact`
trials and no derivation work.

At a local rival ceiling, the client admits the newly returned candidate and
evicts an older one; least-recently-filed is the reference policy, not a
protocol requirement. It never evicts a candidate before the operation that
fetched it has attempted every applicable content-key candidate, the retention
rule of
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements).
Eviction can drop the only retained key for an old render; reopening then needs
another successful unlock while its issuer carrier remains accepted. Longer
retention is host policy, not revocation of capability bytes already delivered.

<a id="frozen-decisions"></a>
## 23. Frozen decisions

This section is editorial history, not protocol authority.

The following decisions were settled on 2026-09-09. The cited normative
sections carry their requirements:

1. The period-chain profile depends on exact `periodKey` behavior and fixes one
   canonical construction. A publisher may use that construction for a family
   generation without selecting a cross-role chain path; chain supply selects
   the additional route duties. The construction is not a second profile kind.
2. The construction transcript of [Canonical construction](#canonical-construction).
3. The geometry pair of [Windows](#windows): complete pair, family override
   before document value, no partial merging, no inference, no default.
4. The fixed `YYMMDDTHHMM` label of [Coordinate labels](#coordinate-labels);
   the construction coordinate is the binary pair window start and position.
5. The carrier of [Extension carrier and client relay](#extension-carrier-and-client-relay):
   the `periodChain` geometry member at the top level of the document, the
   request and the response, and the `periodChainKeys` capability collection
   at `issuerData.<issuerName>.sealed.periodChainKeys` in the document,
   `sealed.periodChainKeys` in the request and `keys.periodChainKeys` in the
   response; relay is a capability of the request path.
6. The `dca-bind-v1|pc` grammar of [Chain envelope BIND](#chain-envelope-bind);
   base `dca-bind-v1` bytes are unchanged.
7. The response member of [Issuer decision and response](#issuer-decision-and-response),
   carrying its own resolved geometry per family. Per-item and per-family
   combination rules for exact and direct grants stay with the base format.
8. Chain state travels over direct transport only; a later profile may define
   a client-bound construction.
9. One message reflects one derivation secret and one resolved geometry per
   family; rival candidates arise across messages, never inside one.
10. No generation identifier on the wire; rival candidates replace it.
11. A tree or range construction starts a new profile and may start a new
    family generation. Reproducing this profile's leaves is optional and needs
    its own proof.
12. The deployment owns the retirement contract; see
    [Deployment retirement contract](#deployment-retirement-contract).

The protocol maxima in [Bounds](#bounds) are fixed v1 profile values; the rule
that every operation has a bound is frozen.

`dca-period-chain-v1` defines one 16-octet chain construction, paired with
`dca-v1-exact-period`. It retains the 32-octet key-derivation secret and the
canonical identifier, transcript, geometry and labels. The previous 32-octet
outputs and alternate compact profile are retired. Root, Step and Leaf vector
evidence remains required; no old-width compatibility interpretation remains.

<a id="security-considerations"></a>
## 24. Security considerations

<a id="capability-monotonicity"></a>
### 24.1. Capability monotonicity

Moving from an exact leaf to positioned chain state broadens authority. The
resolved geometry and the cutoff label make that reach visible to issuer policy
and to client response selection.

<a id="window-confinement"></a>
### 24.2. Window confinement

The construction relies on independently derived terminal/root states and domain-separated
context to confine derivation to one access group, family, profile and window.
Client-side stopping rules add no cryptographic confinement.

<a id="publisher-and-issuer-compromise"></a>
### 24.3. Publisher and issuer compromise

Publisher `keyDerivationSecret` compromise can regenerate the corresponding
generations' window states and exact leaves for every derivable window covered
by that key-derivation secret and profile. Issuer chain-state compromise exposes only the
window-start-through-position range it was supplied; exact issuer material
limits exposure to supplied coordinates.
[spec--security-model.md](spec--security-model.md) states which effects are
protocol-boundary failures and which are defense-in-depth concerns.

<a id="response-transport"></a>
### 24.4. Response transport

An issuer MUST NOT return raw chain state over a transport authorized only for
non-extractable exact AES use. Under
`dca-period-chain-v1`, a chain grant
travels over direct transport only: the
issuer refuses to place chain bytes on client-bound transport, and a client
refuses any that arrive before opening. A client-bound chain construction needs
its own profile with a compatible derivation and storage boundary.

<a id="work-amplification"></a>
### 24.5. Work amplification

No request causes unbounded backward derivation, exact expansion,
rival-candidate trial or response construction; [Bounds](#bounds) names the
limits.


## 25. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function](https://www.rfc-editor.org/info/rfc5869)
- [DCA exact period-key capabilities](spec--period-keys.md)
- [DCA conformance profiles](spec--profiles.md)
- [DCA data format](spec--data-format.md)
- [DCA content protection](spec--content-protection.md)
- [DCA sealed key envelopes](spec--sealed-key-envelopes.md)
- [DCA core protocol](spec--core-protocol.md)
- [DCA response binding](spec--response-binding.md)
- [DCA security model](spec--security-model.md)

## 26. Informative References

- [DCA period-key design companion](guide--period-keys.md)
- [DCA period-chain extension design](guide--period-key-chains.md)
