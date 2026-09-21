# Content-key seal omission

Status: phase-1 prototype extension; implementation-discovery evidence, not protocol authority

An issuer already entrusted with an access-group period capability returns one exact `contentKey`
without the publisher also sealing that content key directly to it. The publisher omits that
issuer's whole `sealed.contentKeys` map, the client forwards the bound `contentData` candidate, and
the issuer opens its own period material, rebuilds the binding and unwraps.

Everything named here is extension-owned and provisional. The wire members, the binding constant
and the per-issuer configuration are this prototype's choices. They are evidence for content-key
seal omission and are not durable format authority.

Base source has only injection seams and imports nothing from this directory.

This extension depends on an exact period-key route, not on period-chain grant
processing. When a publisher family selects the chain extension, the publisher
derives that exact leaf from its canonical chain family. The issuer may receive the leaf
directly, or a chain-capable issuer application may derive it from entrusted
chain state and inject it here. This extension itself never processes chain
state, and neither selecting it nor receiving its returned `contentKey`
requires the client to accept a chain grant.

## Composition

| Role | Module | Stands beside |
| --- | --- | --- |
| publisher | `core-publisher/omissionSealing.js`, with `OmittingSealer.js` | `core-publisher/Sealer.js` |
| client request | `core-client/OmissionRequestBuilder.js` | `core-client/DcaRequestBuilder.js` |
| client open | `core-client/BoundContentKeyResolver.js` | `core-client/ContentKeyResolver.js` |
| request document | `core-shared--client-issuer/OmissionRequest.js` | `core-shared--client-issuer/DcaRequest.js` |
| issuer | `core-issuer/omissionIssuerEngine.js`, with `omissionContentKeySource.js` | `core-issuer/IssuerEngine.js` |
| binding | `core-shared/omissionBind.js` | `core-shared--publisher-issuer/bind.js` |

The binding sits in the universal `core-shared/` slice because all three roles build it, and the
client role may not import the publisher/issuer pairwise slice that holds base `bind.js`. A module
that still repeats base names the lines it copied and why no seam existed.

Four of the six hold base rather than repeat it. `OmittingSealer` holds a base `Sealer` and composes it with
the two roles that Sealer takes, both built by `omissionSealing`: the render's content-key wrap strategy and the
per-issuer supply plan. Base keeps coordinate enumeration, validation order, randomness, fresh content
keys, content encryption, sealing, signing and assembly, and `omissionSealing` reads the per-issuer
deployment members off the `issuers` entries before base sees them. `BoundContentKeyResolver` holds a
base `ContentKeyResolver` and answers after it, so base still applies the response, holds the per-render
content keys and makes the unbound trial. `OmissionRequestBuilder` holds a base `DcaRequestBuilder` and
adds its two members to the request it built, so what the page carries for an issuer is selected in
one place. `omissionIssuerEngine` holds a base `IssuerEngine`, described in the paragraph below.

`omissionIssuerEngine` constructs the base engine with this extension's content-key source. Base runs
the unlock it always ran: the pre-private-key checks, one access decision and its clamp, the
complete-denial refusal, the registration-scoped opening-key lookup with its never-held and retired
rules, BIND opening, per-item errors and `policyData`. It then asks this source for a granted content
key its direct seal did not answer. The seam is base's `contentKeySource`: a source answers one
already-granted content name with a content key's bytes, a miss or one error, and nothing else. It
files no response member, names no period, and widens no grant.

`omissionContentKeySource.js` fills that seam for this extension, and `omissionCandidates.js` chooses
the candidates it tries. `presentedCoordinates` names the content names and period families the
forwarded candidates present, so a policy can decide on coordinates a request carrying no sealed
contentKeys would otherwise not present at all. `candidatesFor` reads this extension's own
`sourceGrants` and answers, for each item, its candidates in the order they are tried: the issuer's
own exact leaf first, then the sealed period blob the request forwarded. Base's opener opens that
blob at the coordinate the candidate named, under the render anchor and the opening key base never
lets go of, and the period key goes to this extension's unwrap. Every candidate is a trial: where
one coordinate will not open, the source moves on to the next candidate, and it reports one failure
for that item only when every eligible candidate is spent. One item has one answer, so a direct seal
that failed leaves no error behind once a candidate answers after it.

Base owns the planner-callable rule. `core-publisher/issuerSupplyPlan.js` refuses a planner that is
not callable, and `omissionSealing` asks base for that same check on the planner it wraps, at
composition, since base sees the wrapper and never the inner planner. The checks on the values an
inner plan declares stay here, because the wrapper narrows `suppliedAccessGroups` before base sees a
plan and base therefore never receives those values.

## Prototype contracts

### 1. Bound wrap

The inner binding is one grammar, five fields, joined on the pipe byte:

```text
dca-seal-omission-bind-v1 | renderId | contentName | accessGroup | t
```

`dca-seal-omission-bind-v1` is this extension's constant and is never `dca-bind-v1`: two grammars
under one token would leave a reader unable to say which produced a value. Field order is fixed as
written. Every field is a non-empty string that cannot carry the delimiter, checked the way
`bind.js` checks its own; `renderId` is 16 bytes in canonical unpadded base64url. Base's
`bindFields` refuses a vector naming a contentName and an accessGroup at once, by design, so this
value cannot be built there.

The value is the AAD of the `contentData` wrap. `core-shared/aead.js` already takes an AAD the base
wrap does not pass, so the bound wrap costs no new primitive and no new field on the entry beyond
its marker.

The bound entry is `{ t, nonce, key, bind: 'dca-seal-omission-bind-v1' }`. The marker tells the two
representations apart: a base reader sees an entry it can describe and cannot open, and this
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
[`spec--content-protection.md`](../../../../docs/spec--content-protection.md)
§ 4, the ordinary wrap strategy in `core-publisher/contentKeyWrap.js`, the two client unwrap calls
in the exact and chain candidate branches of `core-client/ContentKeyResolver.js::#fromCache`, and
every recorded vector carrying a `contentData` wrap. The marker member would then be unnecessary, since there would be one
representation rather than two.

### 2. Request and source selection

The request gains two members:

- `extensions: ['content-key-seal-omission']`, the client's support signal. It is offered rather
  than demanded, grants nothing, and changes nothing the issuer verifies or decides.
- `boundCandidates`, keyed by contentName, each an array of bound entries carrying the
  `accessGroup` and `t` they were read at.

The order is base's and it is load-bearing. Base checks version, registration by exact header kid,
signature and renderId, then calls the policy, and opens nothing before that. The policy interface is
unchanged: it answers `contentNames` out of what the request presented, where presented now means
the union of `sealed.contentKeys` and the forwarded candidates, because an active issuer's request
carries no sealed contentKeys at all.

The policy also decides the coordinate a granted item may be opened through. Its decision carries
`sourceGrants`, a list of `{ accessGroup, periodCount }` this engine clamps to the labels the request
carried, exactly as base clamps a period prefix; a policy naming none falls back to its
`periodGrants`. Naming the two separately lets an issuer open a source it does not hand back.
A candidate outside that set is not tried and no source is asked for it. The outer BIND on a sealed
period blob proves the blob sits at its coordinate, not that this caller may be answered through it,
and an injected leaf source proves neither, so neither can stand in for the decision.

Within the selected set the issuer walks that item's candidates in the order they arrived. The
`accessGroup` and `t` on a candidate are labels: they select which sealed period blob this issuer
tries to open under the outer BIND, and nothing more. The inner binding is then rebuilt from the
verified renderId, the policy's contentName and that same pair. A candidate carried to another
render, content name, access group or period fails authentication and yields no key. There is one
label per blob and no second one beside it.

An issuer holding a period-chain capability injects `exactPeriodLeaves`: application state that
answers `get(registration)` with the exact leaf view held for that authenticated publisher
registration. The intended shape is a `WeakMap` keyed by the registration objects the issuer
application constructed. This extension never derives a chain and never imports the period-chain
extension; `../../test-extensions/period-chain-omission.test.js` is where the two are selected
together.

Base asks for that view once per unlock, against the registration it verified this request against,
and only the selected view travels on. That view takes `(accessGroup, t)` and carries no publisher
selector a caller could get wrong. A registration with no view held is a miss, and no global source
sits under it as a fallback. `(accessGroup, t)` is a coordinate inside one publisher's render and
not a global one, so two registered publishers spelling the same access group and the same period
label would otherwise share one leaf: a registered publisher can copy another's public renderId and
bound candidate and sign that renderId in a valid token of its own, and everything it presents
authenticates. It cannot reach the other publisher's leaf view, because selecting one needs the
registration object. `test/publisher-isolation.test.js` is that case. A retired keyId is never
asked for a leaf at all: base asks no content-key source once the opening key is let go, and
answering from material produced without it would be the rollover answered as though it had not
happened.

A candidate that opens nothing is that item's own error beside the keys that did work, the way base
reports a blob that will not unseal. The response is an ordinary `contentKeys` member. No response
section is added, and the period material the issuer opened as its source never enters the answer:
the issuer walks the granted prefix alone.

### 3. Deployment

Per-issuer configuration on `OmittingSealer`:

| Member | Meaning | Default |
| --- | --- | --- |
| `extensions` | the extensions active for this issuer in this render | none, so inactive |
| `grantable` | the contentNames this issuer must be able to grant | every item of the render |
| `accessGroups` | the period families this issuer's material covers | every group of the render |

A deployment listing `content-key-seal-omission` for an issuer gets
`extensions: ['content-key-seal-omission']` in that issuer's block and no `sealed.contentKeys` at all.
An issuer without it listed is untouched: full direct map, no marker. Direct and derived keys are
never mixed within one active block.

`omissionSealing` turns the three members into one supply plan per issuer. An active issuer is
planned the groups its own material covers, no direct content-key map, the marker as its block's
extra member, and its grantable names as the content names it must reach. An inactive issuer is
planned nothing, which is base's ordinary render. The wrap strategy is the other role and belongs to
the render rather than to an issuer: any active issuer selects the bound wrap for every entry of the
page, and a render with no active issuer keeps base's ordinary wrap.

Two states stop the render with `bad_config`: a grantable item with no bound wrap under a group that
issuer's period material covers, which base refuses while it checks the plans, and an active issuer's
render with no period-key supply at all, which this extension refuses at construction. Base refuses
the plan before the render takes its first random byte, asks the period-key supply, seals to an
issuer or signs, so no partial direct map can be emitted.

This extension spells the narrower set `accessGroups`. Base takes it as the plan's supplied groups,
and the ordinary plan supplies every issuer every group of the render.

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
- **Rollback.** The reverse order. The publisher resumes base direct seals first, and the issuer
  retires support only after the configured render-retirement overlap has passed.
- **Render retirement.** v1 defines no page expiry, so an active render retained past the overlap
  fails once issuer support is gone. `issuedAt` is a stamp and never an expiry.

## Tests

`test/` holds the tests owned by this extension. Run them from `js/v1/`:

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
