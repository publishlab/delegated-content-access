# Chain-key profile implementation

Status: implements the optional chain-key profile `dca-profile-chain-keys`

This implementation-extension directory holds the publisher, request-relay,
issuer and client pieces of the optional chain-key profile. Its required
canonical construction creates positioned chain keys and period keys;
its explicit geometry and role duties are described in
[spec-profile--chain-keys.md](../../../docs/spec-profile--chain-keys.md); its canonical
shared publisher/issuer generation ships here as `core-shared--publisher-issuer/periodFamilyGeneration.js`,
and `core-publisher/periodFamilySupply.js` supplies its per-family publisher
planning. The request relay is explicit in
`core-client/ChainKeyRequestBuilder.js`: base forwards no chain carrier, and
a relay-only client needs neither derivation nor a chain cache, but must still
admit the projected `periodKeys` response through the selected period-key
capability and its base resolver. The issuer side
resolves the relayed geometry and either projects period keys or returns
bounded positioned chain keys. The client interprets chain responses under the complete geometry captured from
the exact associated request and never infers geometry from labels. Request and response
carry the same collection under different member names.
`core-shared--client-issuer/ChainKeyRequest.js` owns the extension request
representation, while
`core-shared--client-issuer/chainKeyCarrierReader.js` reads both carriers,
once per message.

The profile is layered on the period-key profile. A publisher may use the
canonical construction and may supply an issuer period-key members, chain-key
members or both. Chain keys beside a complete period-key supply do not require
that issuer to use them. Chain-only period supply omits that period fallback.
When an operation relies on the retained period route, the request path must
relay the chain keys and the issuer must accept and process them. A separately
authored item content-key route can still resolve an item without using the
chain. The issuer may project period keys for a client that accepts only period
keys. Returning chain keys is a later optional selection that requires both
issuer output and client derivation support over the selected transport.

The item and issuer layers remain separate. Item content keys stay wrapped
under period keys. The issuer block carries period keys, positioned chain keys
from which those same period keys can be derived, or both. Omitting period-key
issuer members saves one sealed envelope per omitted period key without removing
the item's period-key wraps. Within one chain window, a longer authorized
duration changes the cutoff rather than the number of supplied or returned chain
keys.

In this tree `profile` names an injected bundle object, not a source directory.
`referenceProfile.js` is an all-role composition convenience: it imports
publisher, issuer and client modules. A client-only composition imports
`chainKeyClientProfileFor` or `explicitChainKeyClientProfile` from
`core-client/chainKeyClientProfile.js`; the all-role entry reexports those same
function and singleton objects.

The base client copy manifest remains unchanged and does not select this
optional extension. To compose a chain-capable client artifact, copy the base
client manifest's files plus the JavaScript files directly inside this extension's
`core-client/`, `core-shared/` and `core-shared--client-issuer/` directories,
preserving their relative paths. The resulting artifact needs no publisher or
issuer source. Configure the client with a `ChainKeyCache`, the client profile
and `requestBuilderFactory: options => new ChainKeyRequestBuilder(options)`.
The host still supplies the delivery reader, publisher origin, issuer route and
transport, and explicitly selects period-key relay. Importing the all-role entry
would include the other roles instead.

`test/client-profile-copy.test.js` verifies the selected files' complete import
closure and runs a fresh Node process over the copied artifact. That process
opens a real issuer-produced chain response through `createDeliveryClient`,
reopens locally and clears its retained capability. This is a client source-copy
and opening proof; browser hosting and live HTTP configuration remain host duties.

Retained obligations from the rejected forward grant-through-end-of-day construction:

- separate access groups, windows and the Root, Step and Leaf derivations by domain;
- fail closed on malformed, out-of-range and invalid terminal labels;
- retain multiple valid cutoffs in one family without collision.

Canonical extension vector bytes belong to
`test/fixtures/dca-profile-chain-keys.vectors.json`. Its reproducible generator is
`tools/regenerate-canonical-vectors.mjs`; it rebuilds the contexts and
derives 16-byte Root, Step and Leaf values without importing the extension.

`core-shared/chainKeyConstruction.js` fixes the profile's derivation-domain
identifier and its 16-byte chain-key width. It keeps three constants for two
roles: `CHAIN_KEY_PROFILE` names the profile, `CHAIN_KEY_CONSTRUCTION`
selects the construction in its registry, and `CHAIN_KEY_CONSTRUCTION_ID` is the
`constructionId` inside every context, so a profile rename cannot change derived
bytes by accident. It refuses an unknown construction name and every other
chain-key width, and no wire payload length selects a construction.

## Canonical route construction

The `dca-profile-chain-keys` profile holds 16-byte chain keys and derives 16-byte
period keys, wrapped with AES-128-GCM. The protected `contentKey` is also 16 bytes;
the publisher-retained `keyDerivationSecret` remains 32 bytes.

The publisher generation, issuer route and client cache all use the canonical
construction fixed by that profile. Its identifier is never a wire member, and
no reader infers it from length.

Everything that disagrees is refused rather than adapted to. Sealed material,
responses and cache candidates must be 16-byte chain-key or period-key values.

## Base key width

Base wrapping and envelopes use the canonical 16-byte `contentKey`, period key
and chain key. The separate internal envelope transport key remains
32 bytes and is not a delivered DCA capability.

The bounded backward-cutoff family supersedes the rejected construction. Do
not port the rejected derivation, cache, end-of-day or vector fixtures. The
current bounded backward-cutoff construction is fixed by the published
chain-key specification and is implemented here.

## Composition options

This map describes the reference source in this tree. It is an API/composition
observation, not a complete role or profile conformance claim. The
[chain-key specification](../../../docs/spec-profile--chain-keys.md) and selected
[profiles](../../../docs/spec--profiles.md) remain authoritative.

| Selection                      | Reference composition                                                                                                                                                                                                                                         |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Publisher families and windows | `core-publisher/periodFamilySupply.js` supplies the family plan; `../../core-publisher/issuerSupplyPlan.js` selects period-key and chain-key delivery per issuer.                                                                                             |
| Issuer chain input             | Composing `core-issuer/chainKeyIssuerEngine.js` enables chain input. Once the engine is configured for chain input, an authored carrier determines which families are presented; the engine still applies trusted configuration, admission and issuer policy. |
| Issuer output                  | The engine's `representation` option selects `period-keys` (the default) or `chain-keys`.                                                                                                                                                                     |
| Request relay                  | The injected `core-client/ChainKeyRequestBuilder.js` relays chain input; relay alone selects neither issuer output nor client derivation.                                                                                                                     |
| Client chain consumption       | `chainCache` and an admitted `chainKeyProfile` compose retention and derivation with response admission.                                                                                                                                                      |
| Direct transport and retention | `acceptDirectFallback` controls acceptance of direct raw responses; `persistRawPeriodKeys` separately controls retaining raw key bytes, including directly received chain keys.                                                                               |

Chain output is available in direct and client-bound issuer responses when the
corresponding client capability is composed. No reference path selects the
response form from the request. One processor holds one engine with a fixed
representation, so mixed client populations use separately composed endpoints.
Recheck these observations against a later revision before treating them as
current support.

## Publisher composition

`core-shared--publisher-issuer/periodFamilyGeneration.js` builds one immutable generation under one profile's
canonical construction. That generation holds an independently provisioned family root, the
construction identifier the composition selected and one complete geometry, all taken as
already-validated values and snapshotted at construction. The handle carries the profile it
derives under, and a later supply, issuer route or client bundle reads that profile off the
handle to stay on it. It answers the canonical period key at a coordinate, the positioned chain key
at that coordinate, and the period keys that chain key reaches back to its window start.
Every requested label is validated against the geometry the handle holds. It reads no spacing off
a collection of labels, and rotating the secret produces a new handle rather than changing the
old one. The recorded vectors are generated by the in-tree tool from the specification
without importing the extension, and replayed by the implementation tests.

`core-publisher/periodKeySupplyFor.js` exports `periodKeySupplyFor`, which narrows one generation to the `derive(accessGroup, t)` the base
`Sealer` takes, and that call is the whole of what a period-key-only composition sees.
`periodFamilySupply` adds the optional publisher family-plan seam. All selected families share
the delivery's complete top-level `periodGeometry` pair and fixed `YYMMDDTHHMM` labels; there
are no family overrides. Families supplied only as period keys use the same period length and
ordinary labels. Its explicit `chainWindows` count says how many stationary window
terminals are available for issuer supply. When the render actually selects
chain delivery for a group, its item wraps default to the render period only.
`chainItemSlots` optionally selects a positive safe integer of consecutive item
periods, independently of `chainWindows`; for example, set it to `2` when an
ordinary issuer deliberately supplies only the next period key. The same group
shares its item wraps across issuer alternatives. Without actual chain selection,
ordinary `period.slots` still applies, including to configured chain generations
used only for ordinary delivery. A next-window chain key cannot open old-window
markup; that needs retained or freshly authorized matching old-window capability
or another complete authored route.
With `chainWindows: 2`, the publisher entrusts the issuer with the terminal
sources for the current and next independent window. The next terminal carries
the next window's full backward derivation reach immediately; it is not merely
an availability hint or a promise to release that authority later. The issuer
still independently authorizes every capability it returns.

The Sealer acquires each period key and selected chain key
once, before the render takes any random bytes, then emits period keys, chain keys or the explicit
union of both, following each issuer's plan for each access group. The profile's derivation-domain
identifier is not a wire member or a runtime selector.

`periodFamilyContribution(config)` wraps the same `periodFamilySupply(config)`
as the named `chain-keys` publisher contribution. It owns only `periodKeySupply`.
A host can select it with `createPublisher(baseConfig,
periodFamilyContribution(config))`, alongside a compatible omission contribution.
An explicit base supply plus this contribution is refused as two owners. Existing
hand-nested supply compositions remain supported.

The reference `Sealer` emits the complete pair whenever a selected family plan
provides chain geometry, even if every issuer receives only ordinary period
keys. This preserves cached-chain opening at those wraps. A derive-only ordinary
period supply has no chain family geometry and emits no `periodGeometry`; it
must not infer a chain window from its labels. A selected contribution may also
supply a complete matching root pair. A pair supplied by both base and a
contribution must agree. Issuer supply form alone does not decide geometry.

### Per-issuer supply-plan fields

`issuerSupplyPlanFor(issuer, render)` returns the required `contentKeyNames` and
`suppliedAccessGroups`. Those independently select item-key grants and supplied
group capability. Optional `periodKeyDelivery` selects representations **per
supplied group**: omitted group entries default to `["period-keys"]`,
`["chain-keys"]` selects chain-only supply, and `["period-keys", "chain-keys"]`
explicitly supplies both. It does not add a group or choose the issuer's response
representation. Chain delivery requires a configured chain-family source.

Optional `periodKeySourceTs` selects ordinary period-source labels per supplied
group. Omission retains every planned ordinary label; `[]` supplies none for
that group. Labels must be unique canonical planned labels, and the group must
also select ordinary period-key delivery. The field does not change the item's
wrap schedule or the chain terminals supplied under `chainWindows`. Both fields
are publisher configuration; neither is a wire grant or client option. For a
chain-free source, see the [genuine period-only recipe](../../../docs/guide--integration--period-keys.md#a-genuine-period-only-composition).

## Client relay composition

`core-shared--client-issuer/ChainKeyRequest.js` extends the base request view
with the relayed chain carrier while preserving the base request contract for
consumers that do not select this extension.

`core-client/ChainKeyRequestBuilder.js` wraps one already selected request
builder. It carries only the selected issuer's chain families needed by the
unresolved items and the delivery's raw top-level `periodGeometry`. It does not
derive a key or select a response capability. It preserves the supplied pair
for issuer admission rather than inferring one from chain labels.

The wrapper preserves an inner builder's optional `keyFamilies` and
`routeProjection` hooks, including when this request has no stock chain family
to add. Its own period-coordinate admission still checks the relayed stock
chain coordinates; the hooks do not grant keys or widen response admission.

The relay applies only the delivery scopes that decide whether a family has
anything to send, in this order. The inner builder first builds the base
request. A missing or malformed top-level `periodGeometry` pair gives no family
chain geometry, so the relay returns that base request with no chain member
and the issuer can still answer its content and period sections. The client
candidate source likewise offers no cached chain candidate. Next the
relay counts the raw records of the selected issuer's received
`sealed.chainKeys` collection, read from `DcaData.toObject()` across all
families before selecting needed families: more than the trusted capacity
(`maxChainMembersPerMessage`, default 16) omits every chain
member, and more than two in one family omits that family while in-bound
siblings still travel. Another issuer's block never adds to that count. Only
then do the needed-family projection and bounded requested-target subset run.
Every selected label and value travels unchanged, including values that do not
decode as binary strings; issuer admission owns their rejection or reporting.
A port that counts after projection would accept an over-limit carrier as a subset.

The ordinary base request builder emits neither chain `periodGeometry` nor
`sealed.chainKeys`. A deployment selects relay independently through the
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

The reference `chainKeyIssuerEngine` installs that source for its independent
chain grants. Ordinary explicit-label grants may still use the base period-key
route. A chain grant that has no usable representation stays unavailable;
it does not fall back to an ordinary sorted-label grant.

The source counts actual distinct projected period-key candidates against the
288-key family maximum. Its synchronous `checkPeriodKeyOutput(count)` callback
checks all final ordinary `periodKeys`, including base fallback, against the
512-key response maximum. `IssuerEngine` captures and invokes that callback
automatically, including in custom compositions that install the source.
Source decorators forward it. An output overflow refuses the whole exchange
with `too_many_entries`; it never trims rivals. Neither maximum creates a new
base-client admission limit.

The engine declares the processor selections its route needs,
`selectedExtensions: ["chain-keys"]` and, under the chain-key representation,
its `chain-keys` encoder; `createIssuerCore({ engine })` composes both. A host
that names either selection itself must keep the engine's entries, or
construction refuses. The engine's `notDeliveredReport` option reaches the
base engine unchanged: under the default `none` the issuer discloses no family report, so
the `unavailable` report for an authorized old coordinate with no supplied
chain member appears only under `partial` or `complete`. An invalid chain
family stays silent under every setting.

`core-issuer/chainKeyCapabilitySource.js` takes the issuer's input. It admits
one complete top-level geometry pair without label inference or family overrides,
validates stationary-window collections and bounds before opening,
and opens each selected member under the geometry-bearing chain BIND. The
selected construction then projects the clock-started, policy-bounded
reach into ordinary `periodKeys`; relay support therefore does not imply
client chain derivation support. One supplied member is
valid whether it sits at its window's terminal or below it.

A member whose sealed value is not a canonical binary string stays
member-local and does not invalidate its family. The shared carrier reader
keeps every distinct valid value at one cutoff as its own member and drops
the others. A cutoff where no record holds a valid value becomes one entry in
the family's `malformedMembers`, without a value; the issuer source selects a
valid member first. When an authorized
target falls only to a malformed member, the issuer answers `unseal_failed` at
`accessGroup|suppliedT` without decoding or opening the value, as core
Section 7.1 requires. A denied target never reaches the value. A port that
drops malformed members entirely would report the family as
`notDelivered: unavailable` instead, which does not conform.

`referenceProfile.js` composes that source as either period-key projection or
a chain-key response. A deployment selects the chain-key response only for a
chain-capable client. That selection does not authorize its reach: the issuer's
independent policy must permit every coordinate from the stationary window
start through the selected cutoff. A policy that starts partway through a
window can grant those article coordinates as period keys, but cannot grant a
chain prefix containing earlier unauthorized positions. On a chain-response-only
route, new chain grants may therefore wait until a later independent window
begins. Request relay alone does not select that response form.

### Capture the issuer request time

`chainKeyIssuerEngine` needs a finite trusted request instant for its
clock-started selection. Configure `clock: { now: () => new Date() }` for direct
engine calls, or pass the invocation's `capturedAtMs` as finite epoch
milliseconds. An invocation object must contain `capturedAtMs`; it does not
fall back to the configured clock when that field is absent. A direct call may
also pass a valid `Date` as its fourth argument. Do not obtain this instant from
unsigned request fields or recapture it after an asynchronous policy decision.

`endpoint.handleDocument(text, registration, policyInput, capturedAtMs)` forwards
the explicit captured instant. `createBrowserIssuer` captures its host-configured
clock during admission and forwards that value through the processor. The
wrapper's engine clock alone does not replace missing capture in a processor's
invocation object. Configure the clock at the host entry actually executing the
request. Omitting required timing is `bad_config`, not a policy denial.

## Client composition

`explicitChainKeyClientProfile` validates the immutable associated request's complete
geometry before opening or filing any member and queries only the partition selected by the article's explicit
geometry. The `ChainKeyCache` can retain chain keys or expand them in
one backward walk. Under either strategy the cache holds a bounded number of
rival generations per window and queues concurrent writes to one window so they
run one at a time. Material a response has just delivered stays readable only through that
response, and the cache files it in the bounded reusable store once the resolver
reports the article attempt. A read caps the candidates it takes before it
derives from any of them, and skips a chain walk only when the period key that
walk would rebuild was already offered for that wrap. `periodKeys` received on the wire stay in the
ordinary base cache with opaque coordinates.

One pending answer defaults to at most 16 chain members, at most two per family; a
member past either bound refuses with `bad_key`. A composing profile whose
answers carry more passes `maxMembersPerMessage` and `maxMembersPerFamily` to
`new ChainKeyCache(...)`. Each takes a whole number of at least 1, else
`bad_config`. Content groups passes its `maxResponseMembers` and
`maxWindowsPerGroup`.

The rival cap is not a total retained-window limit. Configure the paired
`clock` and `evictionPolicy` options to expire retained windows. The expanded
period-key memo has a separate global 288-entry cap shared across partitions;
one family can displace another family's memo entries. Publisher generation
handles also retain derived keys without automatic eviction when caching is
enabled. A long-running publisher must bound handle lifetimes or disable that
cache with `cache: false`. These are local memory policies, not grant revocation.

## Tests

`test/` contains tests owned by this extension. Run only this extension from
`js/` with:

```sh
npm run test:reference:extension:chain-keys
```

Tests owned by chain behavior remain here when they import sibling extensions.
Shared interactions without a primary feature owner belong in
`../../test-extensions/`. Shared
cases intended for a reference, variant or private implementation target
belong in `../../test-lib/suites/`, with a thin entry point owned by each target.

The reference profile factories pin their construction and output representation.
A conflicting explicit selection is refused as `bad_config`; it is not rewritten.
`issuerEngineFor` returns chain keys, while `explicitIssuerEngineFor` pins ordinary
period-key output even when the caller reuses another endpoint's options.

## Trusted chain-member capacity

The publisher's issuer entry and chain request builder,
carrier readers, issuer source/engine and profile factories expose the same
trusted `maxChainMembersPerMessage` option. The profile factories take it in
their optional second configuration argument. Use the existing
`ChainKeyCache.maxMembersPerMessage` for cache admission, and configure request
byte/entry budgets independently. No carried field can increase these limits.
