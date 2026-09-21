# Period-key chain extension

Status: Informative Draft

This document explains the optional period-chain profiles. Their construction,
geometry, carriers, bounds, and exact transcripts are owned by
[spec--period-key-chains.md](spec--period-key-chains.md). Exact leaf meaning remains owned by
[spec--period-keys.md](spec--period-keys.md).

## Why chains exist

An issuer can return several exact period keys, but exact supply grows with the
number of granted coordinates. A period-chain capability represents a bounded
prefix of exact leaves with one positioned chain state. Within one independently
rooted window, longer access changes the cutoff rather than the number of chain
states. Chains therefore preserve fine period granularity without one delivered
key per period; another touched window adds another state.

Chains remain optional. The period-chain profile fixes one canonical
construction for a selected family generation; exact-only issuers and clients
may support only the exact-period dependency. Exact and chain routes can
coexist because every derived leaf is an ordinary exact period key at its
coordinate.

## Support, presence and use

Keep three facts separate:

1. An actor may implement and enable a period-chain duty.
2. A delivery may carry chain material as one authored alternative.
3. One unlock operation may actually select and use that alternative.

Support does not force use, and presence does not force selection. Exact and
chain issuer members may coexist; an issuer with a complete exact source may
ignore the chain source for an operation. If exact period members are omitted
and an operation relies on the retained period route, the request path must
relay the chain material and the issuer must process it. A separately authored
direct content-key route remains another possible way to resolve the item.

Two publisher sealing layers make that distinction important:

- The item layer wraps its `contentKey` under exact `periodKey[t]` leaves for
  the period route.
- The issuer layer seals to an issuer either those exact period capabilities,
  positioned chain capability from which the same leaves can be derived, or
  both.

Chain-only period supply omits exact members from the second layer. It does not
remove exact-leaf item wraps from the first layer and does not mean the whole
delivery has only one unlock route. The issuer may consume chain input and
return exact leaves, ending chain processing before the client. Returning
positioned chain state selects an additional issuer-output and client-
derivation path.

## Reach

One independently rooted chain covers one stationary time window. A state at a
cutoff derives:

- the exact leaf at that cutoff;
- earlier states and their exact leaves back to the window start; and
- nothing later than the cutoff or inside another independently rooted window.

The issuer grants reach from the window start through the cutoff. That reach is
not reduced to the article currently visible or to a cache horizon. Useful
content reach is the intersection of derivable exact leaves and retained
ciphertext.

```text
window start                                  supplied cutoff
T12 <- T13 <- T14 <- T15 <- T16 <- T17 <- T18 <- T19
 leaf   leaf   leaf   leaf   leaf   leaf   leaf   leaf

state at T19 derives every shown leaf; it cannot derive T20
```

The issuer chooses a cutoff from verified claims, policy, and one issuer-owned
instant. It can return no later than a chain state the publisher supplied to
that issuer. The client names a candidate source; only the issuer grants. The
issuer cannot return reach that its policy did not grant or that the publisher
did not supply.

The issuer uses `periodCount` to limit present and future selection. It does not
hide earlier positions inside the selected window. A publisher that must
exclude older retained artifacts uses exact keys or a separately bounded
window.

## Construction and separation

A publisher starts one family generation with a high-entropy secret, one
construction, and one time geometry. Domain-separated Root, Step and Leaf
operations bind the profile's derivation-domain identifier, access group,
geometry, and window
or position. A different access group is a different logical family. Changing
the secret, construction, or geometry starts a new generation; moving to
another window or position does not. If more than one generation could answer
the same coordinate during migration,
[the chain migration rule](spec--period-key-chains.md#19-generation-identity-and-migration)
defines which candidates the client retains and tries.

Step operations move only backward. Leaf operations produce exact keys and do
not expose derivation state. Issuers and clients use the same transcript. No
role includes BIND in derivation; BIND authenticates the publisher-to-issuer
envelope carrying positioned state.

Under that construction the publisher keeps a 32-octet
`keyDerivationSecret` and produces 16-octet chain states and exact leaves under
one derivation-domain identifier. A future construction or width needs its own
reviewed profile or specification version; an implementation must not infer
width locally or truncate silently.

## Publisher supply and issuer decision

The publisher seals positioned chain state to an issuer one state per envelope.
Its BIND includes the render, access group, supplied position, and complete
geometry. The issuer resolves opening keys within the verified publisher
registration, opens only the selected source coordinate, and projects the
policy cutoff from that state.

When the issuer opens an envelope, it can derive only the key material the
publisher made available through that envelope. The specification calls this
*sourceability*. The issuer then applies its policy to decide what the reader
is entitled to receive. It can return only material that is both available
from the envelope and permitted by policy.

If the publisher gives the issuer every exact leaf in a range, the issuer still
cannot reconstruct chain state from those leaves. If the publisher instead
gives it a chain state, the issuer can derive the covered leaves but need not
return each leaf individually.

The response carries chain capability separately from exact keys and includes
the resolved geometry needed to interpret it. Chain state uses direct delivery
only in the current profiles. A client-bound representation would be a new
selected profile rather than an implicit conversion.

## Client use and caching

The client validates the response against its request and the selected
profile, then may derive only the exact leaves needed by admitted item wraps.
It retains chain state separately from exact keys, partitioned by logical
client, publisher, derivation-domain identifier, access group, geometry, window, and
cutoff. That cache partition is an implementation lookup scope, not another
meaning of logical family.

A later cutoff can dominate an earlier cutoff in the same family generation and
window only when the client derives backward and compares bytes to establish
shared ancestry. No dominance exists across profiles, generations, geometry,
access groups, or windows.

Cache eviction is an implementation choice. It can trigger another issuer
request but does not revoke a state already copied or retained. A reader who
loses entitlement gets no later grant; the delivered prefix still works.

## Operational consequences

Compromise of one delivered chain state exposes its complete derivable prefix.
Compromise of the publisher `keyDerivationSecret` exposes every window and
position for every access group and registered purpose using that secret
material. Root contexts separate derived outputs; they do not contain the
reach of a disclosed input. The selected Step and Leaf purposes consume chain
state rather than that retained input. A new purpose shares its derivation
secret's rotation, retirement, and deletion lifecycle under its own versioned
context.
The publisher must reflect those reaches in key custody, rotation, and incident
response because they are wider than disclosure of one exact leaf.

Windows have independently derived terminal/root states so a state leak cannot
cross into a sibling window. Rotation to a new family generation protects later
renders but does not make old retained ciphertext or delivered capability
disappear. Publishers coordinate cache retention, overlap, backfill, and family
retirement as an operational contract.
