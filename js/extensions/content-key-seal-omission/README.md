# Content-key seal omission

Status: prototype extension; experimental evidence, not protocol authority

An issuer already entrusted with an access-group period capability returns one item `contentKey`
without the publisher also sealing that content key to it. The publisher omits that
issuer's whole `sealed.contentKeys` collection, the client forwards the bound `contentData` candidate, and
the issuer opens its own period material, rebuilds the binding and unwraps.

Everything named here is extension-owned and provisional. The wire members, the binding constant
and the per-issuer configuration are this prototype's choices. They are evidence for content-key
seal omission and are not durable format authority.

Base source has only injection seams and imports nothing from this directory.

This extension depends on a period-key route, not on chain-key grant
processing. When a publisher family selects the chain-key extension, the publisher
derives that period key from its canonical chain family. The issuer may receive the period
key sealed in the publisher's supply, or a chain-capable issuer application may derive it
from entrusted chain keys and inject it here. This extension itself never processes chain
keys, and neither selecting it nor receiving its returned `contentKey`
requires the client to accept a chain grant.

## Composition

| Role             | Module                                                                                 | Stands beside                              |
| ---------------- | -------------------------------------------------------------------------------------- | ------------------------------------------ |
| publisher        | `core-publisher/omissionSealing.js` (`omissionContribution`), with `OmittingSealer.js` | `core-publisher/Sealer.js`                 |
| client request   | `core-client/OmissionRequestBuilder.js`                                                | `core-client/DcaRequestBuilder.js`         |
| client open      | `core-client/BoundContentKeyResolver.js`                                               | `core-client/ContentKeyResolver.js`        |
| request document | `core-shared--client-issuer/OmissionRequest.js`                                        | `core-shared--client-issuer/DcaRequest.js` |
| issuer           | `core-issuer/omissionIssuerEngine.js`, with `omissionContentKeySource.js`              | `core-issuer/IssuerEngine.js`              |
| binding          | `core-shared/omissionBind.js`                                                          | `core-shared--publisher-issuer/bind.js`    |

The binding sits in the universal `core-shared/` slice because all three roles build it, and the
client role may not import the publisher/issuer pairwise slice that holds base `bind.js`. A module
that still repeats base names the lines it copied and why no seam existed.

`omissionContribution(config)` is this extension's publisher contribution. It
reads and snapshots the per-issuer `extensions`, `grantable` and `accessGroups`,
declares them as its issuer configuration members, and wraps the selected supply
planner. When any issuer is active it also owns the render's
`contentKeyWrapStrategy` and requires a `periodKeySupply` owner. A host composes
it with `createPublisher(config, omissionContribution(config))`.
`OmittingSealer` remains a convenience over the same composed base Sealer;
`omissionSealing(config)` exposes its wrap/planner roles and frozen copied
issuer entries for existing callers that spread those roles. Base keeps
coordinate enumeration, validation order, randomness, fresh content keys,
content encryption, sealing, signing and assembly.

`BoundContentKeyResolver` holds a
base `ContentKeyResolver` and answers after it, so base still applies the response, holds the per-render
content keys and makes the unbound trial. `OmissionRequestBuilder` holds a base `DcaRequestBuilder` and
adds its two members to the request it built, so what the page carries for an issuer is selected in
one place. `omissionIssuerEngine` holds a base `IssuerEngine`, described in the paragraph below.

`omissionIssuerEngine` constructs the base engine with this extension's content-key source. Base runs
the unlock it always ran: the pre-private-key checks, one access decision and its clamp, the
complete-denial refusal, the registration-scoped opening-key lookup with its never-held and retired
rules, BIND opening, per-item errors and `policyData`. It then asks this source for a granted content
key its content-key seal did not answer. The seam is base's `contentKeySource`: a source answers one
already-granted content name with a content key's bytes, a miss or one error, and nothing else. Base
files that answer under the content name and checks that the name is granted, but it cannot check
which period coordinate this mechanism may open for an item, or that returned bytes are that item's
key. Core Section 6.3 gives those duties to the trusted source, so this source owns them. It selects
coordinates through `sourceGrants`, authenticates its result through the inner binding, and returns
only the unwrapped item key, never the period key it opened. Section 2 below spells this out. This is
issuer code the deployment trusts, not a sandbox for a hostile source, and the prototype is not an
adopted profile. The trusted source contract is also summarized in
[PORTING.md](../../PORTING.md#response-private-and-wrapped-capability-admission).

`omissionContentKeySource.js` fills that seam for this extension, and `omissionCandidates.js` chooses
the candidates it tries. `presentedCoordinates` names the content names and period families the
forwarded candidates present, so a policy can decide on coordinates a request carrying no sealed
contentKeys would otherwise not present at all. `candidatesFor` reads this extension's own
`sourceGrants` and answers, for each item, its candidates in the order they are tried: the issuer's
own period key first, then the sealed period blob the request forwarded. Base's opener opens that
blob at the coordinate the candidate named, under the render anchor and the opening key base never
lets go of, and the period key goes to this extension's unwrap. Every candidate is a trial: where
one coordinate will not open, the source moves on to the next candidate, and it reports one failure
for that item only when every eligible candidate is spent. One item has one answer, so a content-key seal
that failed leaves no error behind once a candidate answers after it.

Core owns the composition refusals: a second owner of a single-owner seam, a
missing required period-key supply, an issuer member no selected contribution
declared, and an invalid selected planner. Core checks the selected planner
even under wrappers. The checks on the values an inner plan declares stay here,
because this wrapper narrows `suppliedAccessGroups` before base sees the plan.

The contribution keeps its factory-time deployment snapshot. An issuer added
after that factory ran is refused at its first supply-plan request, before
entropy, rather than being treated as ordinary. Both convenience APIs remain
supported; removal requires a separate review and migration of their callers.

## Prototype contracts

### 1. Bound wrap

The inner binding is one grammar, five fields, joined on the pipe byte:

```text
dca-bind-seal-omission | renderId | contentName | accessGroup | t
```

`dca-bind-seal-omission` is this extension's constant and is never `dca-bind-key-envelope`: two grammars
under one token would leave a reader unable to say which produced a value. Field order is fixed as
written. Every field is a non-empty string that cannot carry the delimiter, checked the way
`bind.js` checks its own; `renderId` is 16 bytes in canonical unpadded base64url. Base's
`bindFields` refuses a vector naming a contentName and an accessGroup at once, by design, so this
value cannot be built there.

The value is the AAD of the `contentData` wrap. `core-shared/aead.js` already takes an AAD the base
wrap does not pass, so the bound wrap costs no new primitive and no new field on the entry beyond
its marker.

The same octets are the `wrap_aad` input of the wrap-nonce transcript in
[`spec--content-protection.md`](../../../docs/spec--content-protection.md#41-wrap-nonce) § 4.1. Publisher,
client and issuer each derive the bound wrap's nonce from the render ID, content name, access group,
`t` and this binding, and pass the same binding octets to AES-GCM. A bound wrap therefore gets a
different nonce from an ordinary wrap at the same coordinate, and no member carries either nonce.

The bound record in an item's `keys` is `{ accessGroup, period, key, bind: 'dca-bind-seal-omission' }`.
The marker tells the two representations apart: a base reader sees an entry it can describe and cannot open, and this
extension refuses an entry without the marker rather than trying it unbound. The two are never
mixed at one coordinate. A render with any active issuer carries the bound wrap for every item,
because `contentData` is one shared representation for every reader of that render. A page with an
active issuer therefore needs an extension-aware client for the cached route, including for the
readers of an inactive issuer in the same page.

The client takes `renderId` from `DcaData.renderId`, which decodes the `resourceJWT` payload without
client-side signature verification. It is enough for a local unwrap: a wrong one produces a value
that opens nothing, which is the ordinary
miss. The issuer takes `renderId` from the verified `resourceJWT` claims and from nowhere else.

If this binding were later adopted as the sole unreleased-v1 base representation, these sites
change: the base no-AAD wrap rule in
[`spec--content-protection.md`](../../../docs/spec--content-protection.md) § 4, the ordinary wrap
strategy in `core-publisher/contentKeyWrap.js`, the two client unwrap calls in the period-key and
chain-key candidate branches of `core-client/ContentKeyResolver.js::#fromCache`, and every recorded
vector carrying a `contentData` wrap. The marker member would then be unnecessary, since there would
be one representation rather than two.

### 2. Request and source selection

The request gains two members:

- `extensions: ['content-key-seal-omission']`, the client's support signal. It is offered rather
  than demanded, grants nothing, and changes nothing the issuer verifies or decides.
- `boundCandidates`, an array of bound candidate records. Each names its `contentName` and
  carries the `accessGroup` and `period` it was read at, the wrapped `key` and the marker. Several
  records at one item, group and period stay candidates. A candidate carries no
  nonce: the issuer derives it from the verified renderId, the policy's contentName, the
  candidate's `accessGroup` and `period`, and the inner binding it rebuilds. A carried `nonce` is ignored
  and supplies no IV.

The request builder reports bound candidates as item-key coordinates through
`keyFamilies`, even when the request relays no period or chain keys. It preserves
any key-family flags its inner builder reports. This describes possible response
kinds, not authorization: issuer policy still decides what to release. A
family-only denial cannot suppress a later unanswered item-key request.

The order is base's and it is load-bearing. Base checks version, registration by exact header kid,
signature and renderId, then calls the policy, and opens nothing before that. The policy answers `contentNames` out of what the request presented, where presented now means
the union of `sealed.contentKeys` and the forwarded candidates, because an active issuer's request
carries no sealed contentKeys at all.

The policy receives `sourcePeriodCoordinates`, a copied map of canonical forwarded-candidate labels,
separately from `periodCoordinates` (which still names only sealed ordinary period records).
A held-key-only request therefore exposes source labels without authorizing ordinary period delivery.
The policy also decides the coordinates a granted item may be opened through. Its decision carries
`sourceGrants`, a list of `{ accessGroup, periods }` with explicit labels. This engine intersects
those labels with canonical labels from the request's sealed period keys and forwarded candidates.
When `sourceGrants` is absent, it uses only the validated ordinary labels in `periodGrants`;
independent chain grants do not authorize this auxiliary opening. A present malformed
`sourceGrants` is refused, and an explicit empty list grants no coordinates. Naming the two
selections separately lets an issuer open a source it does not hand back.
A candidate outside that set is not tried and no source is asked for it. The outer BIND on a sealed
period blob proves the blob sits at its coordinate, not that this caller may be answered through it,
and an injected period-key source proves neither, so neither can stand in for the decision.

Within the selected set the issuer walks that item's candidates in the order they arrived.
Only repeated identical wrapped-key material at the same coordinate
is skipped. Distinct admitted material remains an alternative after an earlier
authentication failure, even when its access group and period label match.
Coordinate deduplication does not establish an authenticated match.
Issuer hosts selecting omission must spread `omissionProcessorOptions()` from
`core-issuer/omissionAdmission.js` into their `IssuerProcessor` options. It selects both coordinate
admission and request bounds atomically. Present `boundCandidates` must be an array; record identities
require own valid `contentName`, `accessGroup` and `period`. An invalid identity refuses the whole
request with `binding_failed` before policy, signature or opening-key work. Non-record elements are
skipped; bad key bytes or an unsupported bind marker remain candidate-local failures. An absent
member contributes nothing and unknown record members are ignored. Every raw array element counts
against the reference-local `DEFAULT_REQUEST_LIMITS.maxEntries` cap (currently 16), before deduplication;
excess refuses with `too_many_entries`. Body-byte limits remain the processor host’s responsibility.
The source also validates before policy for direct engine composition; the base trusted-source
fault boundary reports malformed source input there as `internal_error`.
The
`accessGroup` and `period` on a candidate are labels: they select which sealed period blob this issuer
tries to open under the outer BIND, and nothing more. The inner binding is then rebuilt from the
verified renderId, the policy's contentName and that same pair. A candidate carried to another
render, content name, access group or period fails authentication and yields no key. There is one
label per blob and no second one beside it. That inner AEAD check is the source's proof that the
bytes it returns are the granted item's content key for this render; base does not repeat it.

An issuer holding chain keys injects `periodKeyLookup`: application state that answers
`get(registration)` with the period-key view held for that authenticated publisher registration.
The intended shape is a `WeakMap` keyed by the registration objects the issuer application
constructed. This extension never derives from a chain key and never imports the chain-key
extension; `../../test-extensions/chain-keys-omission.test.js` is where the two are selected
together.

Base asks for that view once per unlock, against the registration it verified this request against,
and only the selected view travels on. That view takes `(accessGroup, t)` and carries no publisher
selector a caller could get wrong. Each coordinate callback returns `Promise<Uint8Array|null>` or
`Promise<readonly Uint8Array[]>`: the original single-key form remains supported explicitly. Internally every
result becomes one copied list, memoized for that coordinate within this unlock. Distinct 16-byte
keys are tried in either order; duplicates count once. The reference-local maximum is four distinct
held keys per coordinate, chosen to bound work rather than define a protocol ceiling. A malformed
trusted return or excess distinct keys refuses the whole unlock as `internal_error`; no list is
silently trimmed. Snapshots are discarded between unlocks. A registration with no view held is a miss, and no global source
sits under it as a fallback. `(accessGroup, t)` is a coordinate inside one publisher's render and
not a global one, so two registered publishers spelling the same access group and the same period
label would otherwise share one period key: a registered publisher can copy another's public
renderId and bound candidate and sign that renderId in a valid token of its own, and everything it
presents authenticates. It cannot reach the other publisher's period-key view, because selecting one
needs the registration object. `test/publisher-isolation.test.js` is that case. A retired keyId is
never asked for a period key at all: base asks no content-key source once the opening key is let go,
and answering from material produced without it would be the rollover answered as though it had not
happened.

A candidate that opens nothing is that item's own error beside the keys that did work, the way base
reports a blob that will not unseal. The response is an ordinary `contentKeys` member. No response
section is added, and the period material the issuer opened as its source never enters the answer:
the issuer walks only the explicitly granted labels. Base does not enforce that; this source keeps the period
key because an item grant never authorizes returning it.

### 3. Deployment

Per-issuer configuration, read by `omissionContribution`:

| Member         | Meaning                                                                | Default                  |
| -------------- | ---------------------------------------------------------------------- | ------------------------ |
| `extensions`   | the extensions active for this issuer in this render                   | none, so inactive        |
| `grantable`    | the contentNames this issuer must be able to grant                     | every item of the render |
| `accessGroups` | narrows the period families selected by the required inner supply plan | no further restriction   |

A deployment listing `content-key-seal-omission` for an issuer gets
`extensions: ['content-key-seal-omission']` in that issuer's block and no `sealed.contentKeys` at all.
An issuer without it listed follows its explicit inner supply plan: its selected content keys remain
sealed, with no marker. Sealed and unwrapped content keys are never mixed within one active block.

The contribution's wrapper turns the three members into one supply plan per issuer. An active issuer gets
the groups selected by its inner plan, narrowed by any configured `accessGroups`, no `sealed.contentKeys`
collection, the marker as its block's extra member, and its grantable names as the content names it must
reach. An inactive issuer keeps its inner content-key selection and its supplied groups,
also narrowed by any configured `accessGroups`. The wrap strategy belongs to the render rather
than to an issuer: any active issuer selects the bound wrap for every entry of the page, and a
render with no active issuer keeps the caller's selected wrap strategy, or base's ordinary fallback when none is supplied.
For an active and an inactive issuer alike, the narrowing also drops the inner plan's `periodKeyDelivery` and
`periodKeySourceTs` entries for every group it removed, because each selection names a supplied group. A selection
for a group the inner plan never supplied stays in the plan, and base refuses it.

Two states stop the render with `bad_config`: a grantable item with no bound
wrap under a group that issuer's period material covers, which base refuses
while checking the plans, and an active issuer with no `periodKeySupply`
owner, which core composition refuses when the publisher is built. Base or
another contribution, such as chain keys, may own the supply. An inactive
render claims no single-owner seam; an active omission contribution beside an
explicit caller wrap strategy is refused as two owners. `limits` and
`clientRequestExtraBytes` reach base's request-budget checks. The budget includes the
client support signal and bound candidates, using the same candidate projection
as the request builder. The `omissionSealing` convenience configuration carries
its `itemPreparations` relay as well; retain that member when passing the
configuration to `Sealer`. Plan refusal
precedes the render's first random draw, supply acquisition, sealing and
signing, so no partial content-key collection is emitted.

This extension spells the narrower set `accessGroups`. It intersects that set with the inner plan's
required `suppliedAccessGroups`; omitting the inner selection is refused. The explicit
`wholeRenderIssuerSupplyPlan` helper selects every group when a deployment chooses that scope.

These rules are intended for the states around activation. The code does only the first today:

- **Unsupported issuer.** An issuer composed without this extension ignores both added members: they
  are unknown members of the request document, and base reads neither. Observed: a base
  `IssuerEngine` given an active render's request returns no content key and no error. It neither
  refuses nor answers, which is the fail-closed end but a silent one.
- **Unsupported client.** A client without this extension forwards no candidates, so an active
  issuer has nothing to unwrap and answers with the cached route or with nothing. The publisher must
  not activate for an issuer whose readers cannot forward.
- **Upgrade.** Issuer support is recorded in authenticated onboarding first. The publisher activates
  afterwards, per issuer and per newly produced render.
- **Rollback.** The reverse order. The publisher resumes base content-key seals first, and the issuer
  retires support only after the configured render-retirement overlap has passed.
- **Render retirement.** v1 defines no page expiry, so an active render retained past the overlap
  fails once issuer support is gone. `issuedAt` is a stamp and never an expiry.

## Tests

`test/` holds the tests owned by this extension. Run them from `js/`:

```sh
node --test "extensions/content-key-seal-omission/test/*.test.js"
```

They also run as a named lane, `npm run test:reference:extension:content-key-seal-omission`,
and `npm test` reaches them through its own glob over the package.

`test-lib/` is this extension's own test support: the world every test renders from, the
page-and-request measurement script, and `load.js`, which drives both routes through the issuer
engine at steady and burst concurrency and reports request bytes, subtle-crypto operations per
unlock, throughput and tail latency. Run them the same way:

```sh
node extensions/content-key-seal-omission/test-lib/measure.js
node extensions/content-key-seal-omission/test-lib/load.js
```

A test needing another extension belongs in `../../test-extensions/`.

The load harness uses relayed sealed period keys on its active route and checks the exact returned
content-name set before counting crypto work. Run `node test-lib/load.js --smoke` from this directory
for two one-unlock operation samples without the throughput workload.
