# Period-chain profile implementation

Status: implements the optional period-chain profile currently identified as
`dca-period-chain-v1`

This implementation-extension directory holds the publisher, request-relay,
issuer and client pieces of the optional period-chain profile. Its required
canonical construction creates positioned chain capability and exact leaves;
its explicit geometry and role duties are described in
[spec--period-key-chains.md](../../../../docs/spec--period-key-chains.md); its canonical
publisher construction ships here as `core-publisher/periodFamilyGeneration.js`,
and `core-publisher/periodFamilySupply.js` supplies its per-family publisher
planning. The request relay is explicit in
`core-client/PeriodChainRequestBuilder.js`: base forwards no chain carrier, and
a relay-only client needs neither derivation nor a chain cache. The issuer side
resolves the relayed geometry and either projects ordinary exact keys or returns
bounded positioned chain state. The client consumes explicit-geometry
chain responses and never infers geometry from labels. Request and response
carry the same collection under different member names.
`core-shared--client-issuer/PeriodChainRequest.js` owns the extension request
representation, while
`core-shared--client-issuer/periodChainCarrierReader.js` reads both carriers,
once per message.

`dca-period-chain-v1` remains the current identifier until the planned pre-v1
normalization. The profile is layered on exact-period. A publisher may use the
canonical construction and may supply an issuer exact members, chain members
or both. Chain material beside a complete exact supply does not require that
issuer to use it. Chain-only period supply omits that period fallback. When an
operation relies on the retained period route, the request path must relay the
chain material and the issuer must accept and process it. A separately authored
direct content-key route can still resolve an item without using the chain. The
issuer may project ordinary exact leaves for an exact-only client. Returning
chain state is a later optional selection that requires both issuer output and
client derivation support over the selected transport.

The item and issuer layers remain separate. Item content keys stay wrapped
under exact leaves. The issuer block carries exact leaves, positioned chain
state from which those same leaves can be derived, or both. Omitting exact
issuer members saves one sealed envelope per omitted leaf without removing the
item's exact-leaf wraps. Within one chain window, a longer authorized duration
changes the cutoff rather than the number of supplied or returned chain states.

In this tree `profile` names an injected bundle object, not a source directory.

Retained obligations from the rejected forward grant-through-end-of-day construction:

- separate access groups, windows, roots, steps and leaves by domain;
- fail closed on malformed, out-of-range and invalid terminal labels;
- retain multiple valid cutoffs in one family without collision.

Canonical extension vector bytes belong to
`test/fixtures/dca-period-chain-v1.vectors.json`. Its reproducible generator is
`tools/regenerate-canonical-vectors.mjs`; it rebuilds the retained contexts and
derives 16-byte Root, Step and Leaf values without importing the extension.
Root is the first 16 bytes of the former 32-byte Root because its inputs are
unchanged. Step and Leaf are recomputed from the shortened state and differ.

`core-shared/periodChainConstruction.js` fixes the profile's derivation-domain
identifier and its 16-byte state width. It refuses an unknown identifier and
every other state width, and no wire payload length selects a profile.

## Canonical route construction

`dca-period-chain-v1` holds 16-byte chain state and derives 16-byte exact
leaves, wrapped with AES-128-GCM. The protected `contentKey` is also 16 bytes;
the publisher-retained `keyDerivationSecret` remains 32 bytes.

The publisher generation, issuer route and client cache all use the canonical
construction fixed by that profile. Its identifier is never a wire member, and
no reader infers it from length.

Everything that disagrees is refused rather than adapted to. Sealed material,
responses and cache candidates must be 16-byte state or leaf values.

## Base key width

Base exact wrapping and envelopes use the canonical 16-byte `contentKey`,
exact leaf and chain state. The separate internal envelope transport key remains
32 bytes and is not a delivered DCA capability.

The bounded backward-cutoff family supersedes the rejected construction. Do
not port the rejected derivation, cache, end-of-day or vector fixtures. The
successor construction is not settled; do not port this prototype as that
successor.

## Publisher composition

`core-publisher/periodFamilyGeneration.js` builds one immutable generation under one profile's
canonical construction. That generation holds an independently provisioned family root, the
construction identifier the composition selected and one complete geometry, all taken as
already-validated values and snapshotted at construction. The handle carries the profile it
derives under, and a later supply, issuer route or client bundle reads that profile off the
handle to stay on it. It answers the canonical exact leaf at a coordinate, the positioned chain
capability at that coordinate, and the leaves that capability reaches back to its window start.
Every requested label is validated against the geometry the handle holds. It reads no spacing off
a collection of labels, and rotating the secret produces a new handle rather than changing the
old one. Each profile has its own recorded set of neutral vectors, written from the specification
by two implementations that never read this tree.

`exactPeriodKeySupplyFor` narrows one generation to the `derive(accessGroup, t)` the base
`Sealer` takes, and that call is the whole of what an exact-only composition sees.
`periodFamilySupply` adds the optional publisher family-plan seam: selected families use their
own complete geometry and fixed `YYMMDDTHHMM` labels, while unselected exact families retain
base labels. Its explicit `chainWindows` count says how many stationary window terminals are
available for issuer supply. The Sealer acquires each exact leaf and selected chain capability
once, before the render takes any random bytes, then emits exact keys, chain state or the explicit
union of both, following each issuer's plan for each access group. The profile's derivation-domain
identifier is not a wire member or a runtime selector.

## Client relay composition

`core-shared--client-issuer/PeriodChainRequest.js` extends the base request view
with the relayed chain carrier while preserving the base request contract for
consumers that do not select this extension.

`core-client/PeriodChainRequestBuilder.js` wraps one already selected request
builder. It carries only the selected issuer's chain families needed by the
unresolved items and their applicable raw `periodChain` geometry. It does not
resolve geometry, derive a key, or select a response capability. A malformed
applicable override remains malformed on relay; it is never repaired from the
document default.

The ordinary base request builder emits neither `periodChain` nor
`sealed.periodChainKeys`. A deployment selects relay independently through the
existing Browser/PageLoad request-builder factory. The neutral composition with
content-key seal omission puts the chain builder outside the omission builder,
so each extension's added members reach the finished request without either
extension importing the other.

## Issuer composition

The issuer side runs the ordinary `core-issuer/IssuerEngine`, composed with this extension's
period-capability source. Base runs the unlock it always ran: the pre-private-key checks, one access
decision and its clamp, the complete-denial refusal, the registration-scoped opening-key lookup with
its never-held and retired rules, BIND opening, per-item errors and `policyData`. It then asks this
source to represent the period capability it granted. The seam is base's `periodCapabilitySource`,
and base asks it twice. It asks for a selection first, before any opening key is looked up: given one
granted access group and the count the policy answered, the source names the coordinates it will
represent, or misses. Only a selection counts toward what this request was granted. Base then asks it
to represent what it selected: for each period it answers a label with either key bytes or the one
failure recorded for that label, under an opener confined to the selected coordinates.

The reference `periodChainIssuerEngine` installs that source for the issuer's
whole period route. One engine instance therefore does not mix a chain-owned
family with a plain exact family. A deployment needing that finer routing must
compose separate routes or supply a family-aware source; the reference wrapper
does not infer it from request contents.

`core-issuer/periodChainCapabilitySource.js` takes the issuer's input. It resolves
the complete document/default or family-override geometry without label
inference, validates stationary-window collections and bounds before opening,
and opens each selected member under the geometry-bearing chain BIND. The
selected construction then projects the clock-started, policy-bounded
reach into ordinary exact `periodKeys`; relay support therefore does not imply
client chain derivation support. One supplied member is
valid whether it sits at its window's terminal or below it.

`referenceProfile.js` composes that source as either exact projection or
direct chain response. A deployment selects the direct chain response only for a
chain-capable client, and in selecting it authorizes reach from the stationary
window start through the selected cutoff. Request relay alone does not select
that response form.

## Client composition

`explicitPeriodChainClientProfile` validates response geometry before filing
any member and queries only the partition selected by the article's explicit
geometry. The `PeriodChainCache` can retain chain state or expand it in
one backward walk. Under either strategy the cache holds a bounded number of
rival generations and queues concurrent writes to one window so they run one at
a time. Material a response has just delivered stays readable only through that
response, and the cache files it in the bounded reusable store once the resolver
reports the article attempt. A read caps the candidates it takes before it
derives from any of them. Exact `periodKeys` received on the wire stay in the
ordinary base cache with opaque coordinates.

## Tests

`test/` contains tests owned by this extension. Run only this extension from
`js/v1/` with:

```sh
npm run test:reference:extension:period-chain
```

Tests requiring another extension belong in `../../test-extensions/`. Shared
cases intended for a reference, variant or private implementation target
belong in `../../test-lib/suites/`, with a thin entry point owned by each target.
