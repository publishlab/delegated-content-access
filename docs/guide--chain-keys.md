# Chain-key extension

Status: Informative Draft

This document explains the optional chain-key profile. Its construction,
geometry, carriers, bounds, and exact transcripts are owned by
[spec-profile--chain-keys.md](spec-profile--chain-keys.md). Period-key meaning remains owned by
[spec-profile--period-keys.md](spec-profile--period-keys.md).

The [illustrated companion](guide--key-flow--diagrams.md) walks through
publisher sealing, issuer delegation across two windows, and client opening.

The [label-mapping guide](guide--chain-keys--label-mapping.md) gives calendar-library
advice, optional integer conversion arithmetic and worked coordinates.

## Why chains exist

An issuer can return several period keys, but period-key supply grows with the
number of granted coordinates. A **chain key** represents a bounded
prefix of period keys with one positioned, derivation-capable secret. It is
not the **period key** that opens an item
wrap. Within one independently rooted window, longer access changes the cutoff
rather than the number of chain keys. Chains therefore preserve fine period
granularity without one delivered key per period; another touched window adds
another chain key.

Chains remain optional. The chain-key profile fixes one canonical
construction for a selected family generation; issuers and clients may
support only the period-key dependency. Period-key and chain-key supply can
coexist because every period key derived from a chain key is an ordinary period
key at its coordinate.

The profile adds five goals to those of period keys:

- Expressive delegation: the publisher and issuer can grant per-period, sparse,
  scheduled or compact cutoff-based authority without redesigning article
  encryption for each policy.
- Compact broad supply: a publisher need not seal hundreds of period keys for an
  issuer intentionally trusted for a whole window.
- Narrow authority when wanted: a publisher can withhold derivation reach and
  give an issuer only period keys for selected coordinates.
- Capability combinations that compose: a chain-input issuer can serve a
  period-key-only client, and one period-key-only actor does not force every
  other actor onto the least efficient supply form.
- Deterministic, debuggable time geometry: period and window boundaries are
  reproducible across implementations and visible in test vectors.

Period-key supply gives the issuer authority over exactly the supplied periods,
contiguous or sparse, and no ability to derive omitted periods; it allows a
low-complexity issuer tier and straightforward period-key processing and
conformance tests. Its irreducible cost is one key value plus coordinate
metadata per supplied access-group and period coordinate. Chain supply gives
compact publisher-to-issuer supply, fine-grained period-key projection by
issuer policy, compact grants from the window start through an authorized
cutoff, and room to vary grant duration without resealing every period key.

Counts make the difference concrete. With `I` issuers, `G` access groups, `P`
supplied period keys and `W` touched chain windows, the publisher-to-issuer
capability values are:

```text
period key values: I × G × P
chain key values:  I × G × W
```

For one twelve-hour window of 144 five-minute periods, three access groups and
two issuers, that is `2 × 3 × 144 = 864` period-key values against
`2 × 3 × 1 = 6` chain-key values. These numbers are illustrative, not protocol
defaults. They count key material per render, not encrypted carriers or
measured bytes: chain-key and period-key envelopes alike bind `renderId` and
are sealed once per render, and the selected chain carrier holds one positioned
chain key per envelope, so this layout produces 864 versus six public-key
envelopes. A batched issuer-targeted carrier is not selected and would need its
own specification. Key values, encrypted carriers and encoded bytes, including
labels, geometry metadata and response expansion, are separate measures. Even
where two period keys and two chain keys tie across a window boundary, their
supplied authority differs: two period keys expose two named coordinates, while
two root chain keys let issuer policy select many fine-grained coordinates
across two windows.

## Support, presence and use

Keep three facts separate:

1. An actor may implement and enable a chain-key profile duty.
2. A delivery may carry chain keys as optional period-key supply to an issuer.
3. One unlock operation may actually select and use that supply.

Support does not force use, and presence does not force selection. Period-key
and chain-key issuer members may coexist; an issuer with a complete period-key
source may ignore the chain-key source for an operation. If period-key members
are omitted and an operation relies on the item's period-key-wrap alternative,
the request path must relay the chain keys and the issuer must process them. A
separately authored item content-key alternative, through which the issuer
returns the item's content key, remains another way to open the item.

Six configuration facts decide whether and how a chain route is used, and each
has its own actor: the publisher selects key supply for an issuer and family
generation, the client host selects relay and response acceptance for its client
population, and the issuer selects input processing and response forms under its
trusted configuration and policy.

1. Publisher supply: the publisher enables the canonical construction for named
   family generations and configures whether each issuer receives period-key
   members, chain members or both.
2. Issuer input: the issuer enables or disables chain input for that publisher
   relationship or family.
3. Issuer output: the issuer enables, independently of input, whether it may
   answer with projected period keys, with a returned chain key, or with either.
4. Request relay and admission: the client has selected the relay capability,
   and a client accepting projected period keys admits them against the relayed
   request's resolved geometry and member reach.
5. Client derivation: the client population making the request is enabled to
   accept and derive from a chain key.
6. Transport mode: the selected issuer-to-client transport mode can safely
   deliver the response form.

How issuer supply, request path and client support combine:

- Period-key supply, period-key-only request, period-key-only client: the issuer
  returns authorized available period keys.
- Period-key supply, period-key-only request, chain-capable client: the issuer
  still returns period keys; period-key supply cannot reconstruct a chain key.
- Chain supply, period-key-only request, any client: the chain carrier never
  reaches the issuer, so it supplies nothing unless a period-key route is also
  configured.
- Chain supply, chain relay, period-key-only client: the issuer projects and
  returns authorized period keys.
- Chain supply, chain relay, chain-capable client: the issuer may return period
  keys or an authorized cutoff chain key.
- Period-key and chain supply, chain relay, any client: the issuer grants from
  the authorized union of sourceable member reach.

Two publisher sealing layers make that distinction important:

- The item layer wraps its `contentKey` under period keys `periodKey[t]` for
  the period-key-wrap alternative.
- The issuer layer seals to an issuer either those period keys, positioned
  chain keys from which the same period keys can be derived, or both.

Chain-only period supply omits period-key members from the second layer. It does
not remove period-key item wraps from the first layer, so the item's
period-key-wrap alternative and any other issuer block's period-key supply
remain. The issuer may consume chain keys and return period keys derived from
them, ending chain processing before the client. Returning a positioned chain
key selects an additional issuer-output and
client-derivation path.

## Starting with period keys and enabling chains later

A simple publisher can generate independent random period keys. It configures
the shared `periodMinutes`, omits wire `periodGeometry` and needs no chain
derivation secret or `chainsPerDay`. Enabling chains changes new renders to a
new generation of derived period keys. Cached old keys fail to open those new
wraps, and the client unlocks normally. Old keys still open matching old pages.
In the JavaScript reference, a selected chain-supply family wraps each item only
at its render period by default. `periodFamilySupply({ families, chainWindows,
chainItemSlots: 2 })` explicitly adds the next period as another item wrap.
`chainItemSlots` is a positive safe integer and defaults to one; `chainWindows`
independently controls how many window capabilities the publisher supplies.
Ordinary routes without selected chain supply retain `period.slots`. Each slot
uses the delivery's `periodMinutes`, not the former `period.length`.

One render-period wrap reduces article metadata without reducing a chain's
reach. A later key in the same window can still derive that period key. A key
from the next independent window cannot: opening an old cached page needs a
retained matching old capability, a newly authorized key from that page's old
supply, or another complete route. Supplying the next window does not create
an item wrap there or authorize recovery of the old window. Missing supply or
a policy denial remains a refusal.

If an ordinary issuer shares the group's wrap, supply the render-period key to
that route. A route supplying only a later period needs an explicitly authored
matching extra wrap or another complete item route. A client without chain
support can receive projected period keys when its configured relay and issuer
support chain input; a baseline-only client instead needs an item-key route.
These are reference authoring choices, not new mandatory profile duties.

The publisher can initially seal both the new period keys and their chain
sources to the issuer. Existing routes use the period-key members. Later, a
configured client relay and issuer can use the chain sources already in that
same article. The issuer can keep returning ordinary period keys; returning
chain keys requires a separately enabled response path and capable client.
Changing the issuer's delivery form does not change the publisher's key bytes.

An article's forward overlap wrap does not require another chain source.
Consider a page rendered in the final period of a window. Its current wrap
uses a period key reachable from the supplied chain. Its overlap wrap can use
the next window's first period key, supplied as an ordinary period-key member.
Both are generated by the selected construction, but the publisher sends only
the selected current-window chain. Privately deriving the next period key is
different from handing out its window's chain capability.

The overlap wrap can also remain available only for cached keys: a reader can
obtain the next period's key from a later article and use it on this older
page. The publisher need not supply that overlap key in this page when its
current-period or item content-key route already completes the item and no
separate overlap-key acquisition was promised.

When the overlap coordinate becomes current, the publisher uses the same key
bytes. A reader holding that key can open the older cached page through its
overlap wrap and matching new pages without another unlock. Issuer policy
still decides whether to grant that period key. An overlap within the current
chain's own reach is already derivable and needs no separate chain entry.

## Reach

One independently rooted chain covers one stationary time window. A chain key at a
cutoff derives:

- the period key at that cutoff;
- earlier chain keys and their period keys back to the window start; and
- nothing later than the cutoff or inside another independently rooted window.

The issuer grants reach from the window start through the cutoff. That reach is
not reduced to the article currently visible or to a cache horizon. Useful
content reach is the intersection of derivable period keys and retained
ciphertext.

```text
window start                                  supplied cutoff
T12 <- T13 <- T14 <- T15 <- T16 <- T17 <- T18 <- T19
P12    P13    P14    P15    P16    P17    P18    P19

chain key at T19 derives every shown period key; it cannot derive T20
```

The selected request path relays chain source members unchanged and names the
desired unresolved article-wrap labels in `requestedPeriodKeys`. Those unsigned
labels grant nothing. The issuer independently authorizes reusable period-key
reach, selects permitted article coordinates that the supplied members can
produce, and does not require current-time supply for an otherwise usable old
article target.

Separately, issuer policy may select `futurePeriodCount`, a maximum optional
current-and-future horizon starting from one issuer-owned instant. Zero grants
no future periods but does not deny independently authorized article targets.
A future gap does not suppress those targets. The horizon does not hide earlier
positions inside a returned chain key's window.

Response form is a separate trusted agreement. For a chain result the issuer
checks every position from the window start through the returned cutoff against
policy and valid supply; chain-output configuration or client support never
authorizes that prefix. It can narrow a candidate cutoff to an earlier selected
target with a permitted prefix. When the prefix remains too broad, it projects
permitted period keys only if the selected response agreement permits them;
otherwise it returns no such capability. No returned cutoff can exceed the
source member's supplied position. A publisher that must exclude older retained
artifacts uses period keys or a separately bounded window.

Take one family with 60-minute periods in two independently rooted 12-hour
windows per UTC day, and an issuer that evaluates the request at 13:00. `C[i]`
and `P[i]` are the positioned chain key and period key within the stated window;
the times, geometry and permissions are hypothetical, not protocol defaults or a
policy template. Three cases have distinct outcomes:

- Old article: policy independently permits reusable group reach at the
  article's 04:00 coordinate in the 00:00-12:00 window, and its
  publisher-supplied `C[11]` opens. `P[4]` can be projected even though the
  current window began at 12:00; a `C[4]` response additionally requires
  permission for positions 0-4.
- Missing old source: policy permits the same 04:00 reach, but the request
  supplies only a member in the 12:00-24:00 window. No key for 04:00 results,
  because the newer member cannot derive backward across the window boundary;
  with no family capability returned, an `unavailable` report can describe the
  independently authorized selection.
- Prefix exceeds policy: policy permits reusable group reach only at position 4
  in the old window, and valid old-window `C[11]` supply exists. Returning `C[4]`
  would also grant positions 0-3, so the issuer returns `P[4]` if the selected
  response agreement permits period keys; otherwise it returns no such
  capability.

The reference chain issuer engine discloses family reports only when its host
sets `notDeliveredReport` to `partial` or `complete`; the default, `none`,
discloses none. The issuer may omit this report under its disclosure policy.
Silence does not indicate `unavailable` and does not authorize conditional
fallback.

Supplying the root chain key for the next independent window grants the issuer
that next-window ceiling early. That may suit rollover, but it is an authority
decision, not a free consequence of overlap authoring.

## Construction and separation

A publisher starts one family generation with a high-entropy secret, one
construction, and one time geometry. Domain-separated Root, Step and Leaf
operations bind the construction's derivation-domain identifier, access group,
geometry, and window
or position. A different access group is a different logical family. Changing
the secret, construction, or geometry starts a new generation; moving to
another window or position does not. If more than one generation could answer
the same coordinate during migration,
[the chain migration rule](spec-profile--chain-keys.md#19-generation-identity-and-migration)
defines which candidates the client retains and tries.

The publisher creates the root chain key at the window's last period, then
derives earlier chain keys backward from it. Step operations move only
backward. Leaf operations produce period keys and do not expose the deriving
chain key. Issuers and clients use the same transcript. No
role includes BIND in derivation; BIND authenticates the publisher-to-issuer
envelope carrying a positioned chain key.

Under that construction the publisher keeps a 32-octet
`keyDerivationSecret` and produces 16-octet chain keys and period keys under
one derivation-domain identifier. A future construction or width needs its own
reviewed profile or specification version; an implementation must not infer
width locally or truncate silently.

## Publisher supply and issuer decision

The publisher seals positioned chain keys to an issuer, one key per envelope.
Its BIND includes the render, access group, supplied position, and complete
geometry. The complete pair is top-level `periodGeometry`, shared by every
ordinary and content-group chain in that delivery; no group override is
available. The issuer resolves opening keys within the verified publisher
registration, opens only the selected source coordinate, and projects the
policy cutoff from that chain key.

When the issuer opens an envelope, it can derive only the key material the
publisher made available through that envelope. The specification calls this
*sourceability*. The issuer then applies its policy to decide what the reader
is entitled to receive. It can return only material that is both available
from the envelope and permitted by policy.

If the publisher gives the issuer every period key in a range, the issuer still
cannot reconstruct a chain key from those period keys. If the publisher instead
gives it a chain key, the issuer can derive the covered period keys but need
not return each period key individually.

The response carries chain keys separately from period keys. The client uses
the complete geometry captured from the exact associated request to interpret it;
the response echoes no geometry. The issuer may return a chain key
in direct transport mode as raw bytes, or in client-bound transport mode
protected for the selected client by an existing client-bound method. The
transport mode does not change its cutoff reach. Client-bound transport mode
does not keep the chain key byte-free during derivation.

## Client use and caching

The client validates the response against its request and the selected
profile, then may derive only the period keys needed by admitted item wraps.
It retains chain keys separately from ordinary period keys within the logical
client context. Chain derivation is partitioned by publisher security namespace,
access-group family, any configured issuer partition, the selected chain-key
profile and canonical construction, and the resolved `chainsPerDay`/`periodMinutes`
pair. Window and cutoff identify retained entries and their reach. For an article,
the client derives only in the partition selected by that article's resolved
geometry under its configured profile; it does not search unrelated geometry
partitions. Different generation bytes remain bounded rival candidates within
the applicable partition. [Chain keys §19](spec-profile--chain-keys.md#19-generation-identity-and-migration)
owns these rules. An ordinary period key obtained from a chain remains subject
to the period-key cache boundary; derivation provenance does not make chain
geometry a permanent condition on its use.

A later cutoff can dominate an earlier cutoff in the same family generation and
window only when the client derives backward and compares bytes to establish
shared ancestry. No dominance exists across profiles, generations, geometry,
access groups, or windows.

Later cache eviction is an implementation choice. Finite retained-rival and
combined-trial bounds still apply, and a key remains usable by the operation
that obtained it until that operation has attempted every applicable content-key
candidate, including across storage-view transfers or expansion. See
[chain keys §22.2](spec-profile--chain-keys.md#222-local-retention-policy). Eviction can
trigger another issuer request but does not revoke a chain key already copied
or retained. A reader who
loses entitlement gets no later grant; the delivered prefix still works.

The two retention strategies trade differently:

- Retaining a chain key preserves compact local regeneration for old matching
  renders but needs a chain-aware resolver and protected chain-key storage.
- Expanding period keys reuses the simple period-key cache but consumes more
  entries, and an evicted period key cannot be regenerated after its source
  chain key is discarded.

A client may cache intermediate chain keys to spend less derivation work; the
specification's work bounds assume no cache.

## Operational consequences

Compromise of one delivered chain key exposes its complete derivable prefix.
Compromise of the publisher `keyDerivationSecret` exposes every window and
position for every access group and registered purpose using that secret
material. Root contexts separate derived outputs; they do not contain the
reach of a disclosed input. The selected Step and Leaf purposes consume
chain keys rather than that retained input. A new purpose shares its derivation
secret's rotation, retirement, and deletion lifecycle under its own versioned
context.
The publisher must reflect those reaches in key custody, rotation, and incident
response because they are wider than disclosure of one period key.

Windows have independently derived root chain keys so a chain-key leak cannot
cross into a sibling window. Rotation to a new family generation protects later
renders but does not make old retained ciphertext or delivered capability
disappear. Publishers coordinate cache retention, overlap, backfill, and family
retirement as an operational contract.

Replacing the `keyDerivationSecret` while keeping the same profile and geometry
runs in five steps:

1. The publisher generates or provisions a replacement `keyDerivationSecret`.
2. Newly rendered items use canonical period keys and issuer capability
   collections from each new dependent family generation.
3. A client holding only old-generation material tries its cached candidates,
   misses, unlocks the new render once and files the returned period key or
   chain key beside the existing candidates.
4. Old cached renders keep using old cached candidates, or unlock through their
   retained old issuer carrier while it remains accepted and current issuer
   selection can still return a period key matching an old item wrap.
5. Later acceptance retirement and key-derivation-secret deletion follow the
   separate lifecycle rules of the chain-key specification.

Opening the new issuer carrier uses the issuer's opening key and verified
publisher evidence, not a client-held old `periodKey`; the new period capability
is the result of unlock, not a prerequisite for it. Scheduled rollover may align
with a new window to reduce same-coordinate coexistence, but an emergency
mid-window rollover remains representable.
