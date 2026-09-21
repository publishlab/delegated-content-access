# Profile tests

This directory holds small JavaScript reference scenarios for named DCA
profiles. Each scenario requests one profile or a meaningful set of independent
profiles, resolves the baseline and transitive dependencies, and exercises the
affected roles through real reference seams.

These tests show that the JavaScript reference pieces compose at the recorded
source revision. They are not independent conformance evidence and do not
prove that the specifications are correct.

The [JavaScript reference README](../README.md#how-profile-selection-reaches-role-code)
explains how a resolved profile becomes typed role configuration rather than a
profile-name branch throughout core code. This directory records the evidence
that those independently configured roles compose.

## Target canonical files

The target file set uses the current authoritative profile identifiers:

```text
dca-v1-direct-https.test.js
dca-v1-browser-origin.test.js
dca-v1-exact-period.test.js
dca-period-chain-v1.test.js
dca-v1-content-representations--gzip.test.js
dca-v1-client-bound-ecdh-p256.test.js
dca-v1-client-bound-rsa-oaep.test.js
```

Only the exact-period file exists today. Until another complete scenario moves
here, the coverage index below names its focused interim evidence rather than
pretending the target filename exists.

Rename the period-chain file only with the coordinated identifier migration.
The `--gzip` suffix identifies the concrete transform used by the
content-representations scenario; it does not create a gzip profile. Join two
independent requested leaves with `--` only when their shared seam requires a
complete scenario that neither leaf establishes alone.

## What belongs here

Use one file named for each requested profile leaf. The file states its full
resolved profile closure, affected roles, scope-specific selections and final
observation. A second scenario belongs only when a choice changes:

- which role processes a value;
- what representation crosses an actor boundary;
- which fallback form is omitted;
- terminal, retry or fallback behavior;
- key custody or derivation location;
- an authorization or origin boundary; or
- an explicit composition or incompatibility rule.

Detailed validation, malformed-input, cryptographic, bound and cache-policy
cases remain with their focused owners. One extension's tests live under
`extensions/<name>/test/`; interactions requiring two or more implementation
extensions live under `test-extensions/` and are linked from the profile
coverage index rather than copied here.

Tests in this directory compose implementation components, not other tests.
Never import a `*.test.js` file. Reuse a test-only helper only when it performs
setup or observation and does not implement the behavior being tested.

Inventory before adding a canonical file. When one existing scenario already
meets the complete-profile criteria, either move that scenario here if
profile ownership is clearer or record it as interim evidence until extraction
is worthwhile. Do not retain the old assertion and add a wrapper or duplicate
merely to populate this directory.

## Dependency and combination rule

The filename follows the requested profile leaf; dependencies are explicit in
the scenario rather than repeated as separate combinations. For example, a
period-chain scenario resolves the baseline and exact-period profiles before
the period-chain leaf. Baseline plus exact-period is therefore not another
period-chain combination.

Test a set of independent leaves only when they meet at a shared seam or an
authority defines a joint rule. Do not enumerate the Cartesian product. A
single representative combination is enough when several key-delivery forms
converge on the same authenticated content-opening seam.

For period chains, useful distinctions include chain input projected to an
exact result for an exact-only client, chain input returned as chain state to a
chain-aware client, and exact plus chain publisher supply where presence does
not force chain use. Direct content-key delivery remains an independent
baseline alternative. One response may carry exact results for one family and
chain results for another. On a chain-owned route one family returns exact or
chain, not both; an explicitly configured exact-and-chain input union does not
change that response rule.

## Selection is not field presence

A scenario keeps these states distinct:

1. a role implements profile behavior;
2. trusted deployment or integration configuration enables it;
3. the publisher authors one or more alternatives;
4. the operation selects one or more usable alternatives; and
5. the receiving role admits and applies the selected result.

No generic profile identifier travels in a DCA request or response. A client
integration knows its enabled profile set or deployment preset through trusted
configuration. The signed delivery supplies authored alternatives. The
operation's route selector intersects those facts; member presence alone does
not enable or select a profile. `requestedProfiles` and `resolvedProfiles`
describe capability and dependency closure, not which route one operation
used.

Client relay is not authorization and is not a trusted instruction to the
issuer. A client chooses which publisher-supplied ciphertexts to present; a
bad client can omit a usable capability or send extra authored alternatives,
but cannot thereby expand the publisher-authenticated source material or the
issuer's policy grant. The issuer independently validates the request,
authenticates opened coordinates and returns only policy-authorized capability.

The issuer already holds trusted route and profile configuration. No signed
client profile list is needed for authorization. If a deployment later chooses
dynamic route discovery, facts that change issuer interpretation must come
from authenticated publisher or endpoint metadata. This version instead uses
the host's [trusted route configuration](../../../docs/guide--unlock-fallback.md#why-routing-does-not-belong-in-publisher-data).

The issuer has the corresponding trusted selection for the input and output
forms it processes. A baseline-only issuer ignores optional exact and chain
sections rather than parsing them. An exact-period issuer may process selected
exact input. A period-chain issuer may process selected chain input and may
project exact output or, for a selecting client, return chain state.

The initial selection scenarios establish that:

- a baseline-only client uses a complete direct route and does not relay exact
  or chain material merely because the delivery carries it;
- unselected optional material, including malformed profile-local coordinates,
  does not gain parsing or route meaning beside that usable direct route,
  subject to the protocol's outer resource limits;
- an exact-period client may select exact material without selecting chain;
- a period-chain client resolves exact-period support but still chooses exact,
  chain or both authored request routes explicitly;
- exact plus chain presence does not automatically select either or both; and
- a delivery with no complete route selected for that client does not produce
  a request from unsupported material. The integration authority decides its
  final no-route observation before the test pins it.

## Minimum evidence for each profile

Each profile file states the requested leaf, resolved dependencies, affected
roles, scope-specific selections, real actor seams crossed and final
observation. It links the focused suites that own exhaustive behavior and says
which materially different scenarios remain elsewhere.

The scenario demonstrates one successful complete composition. It also covers
an unselected or unsupported case when silent activation would be unsafe and
observes the profile-specific boundary rather than only final plaintext. A
role the profile does not affect stays unchanged when that is meaningful.

For a profile that changes capability representation, authorization stays
orthogonal: the same positive grant reaches usable content through each
permitted selected form, while a denial yields no usable capability. A test
must not make a route representation decide entitlement.

Dependency resolution will eventually come from the checked profile
catalogue. Until then, record the expected closure here and in the file; do not
create another executable dependency graph merely for these tests.

## Profile checklist

### `dca-v1-direct-https`

- Resolve the baseline alone.
- Publisher produces one protected item, assertion and direct issuer route.
- Issuer verifies, authorizes and returns a direct content key through the
  ordinary HTTPS JSON response shape.
- Client associates the response and opens the item.
- Period, representation, browser-origin and client-bound behavior is absent.

### `dca-v1-browser-origin`

- Resolve baseline plus browser-origin.
- Publisher signs the delivery origin, the browser boundary supplies it, and
  the issuer admits the exact match before protected work.
- A mismatching observed origin reaches no policy, cache or opening key.
- Keep credentialed-mode permutations in focused tests unless they change
  another crossing.

### `dca-v1-exact-period`

- Resolve baseline plus exact-period.
- Publisher authors exact period wraps and matching issuer capability.
- Request relays an unresolved exact coordinate; issuer returns an authorized
  exact leaf; client files it and opens the item.
- A second item in the same period opens from retained exact capability without
  another issuer call.
- No chain material participates.

The canonical scenario is
[`dca-v1-exact-period.test.js`](dca-v1-exact-period.test.js). It disables the
publisher's direct route, selects exact relay and issuer input independently,
opens the first item through the returned exact leaf, and opens a second item
from retained capability without another issuer call. The focused request and
issuer suites separately prove that carried exact material stays inactive when
the applicable selection is off.

### `dca-period-chain-v1`

Resolve baseline, exact-period and period-chain. Exercise two complete forms
because issuer output changes downstream role requirements:

1. Publisher supplies chain-only period material, the request relays it, the
   issuer projects exact leaves, and an exact-only client opens the item.
2. Publisher supplies chain-only period material, the issuer returns positioned
   chain state, and a chain-aware client derives the exact leaf and opens the
   item.

Also establish that:

- exact plus chain publisher supply does not force the issuer to use chain;
- a relied-on chain-only route cannot silently use omitted exact
  publisher-to-issuer material;
- an independently authored direct content-key route remains usable;
- an issuer does not return chain state to a client that did not select it; and
- a chain-capable client still accepts an exact result inherited through the
  dependency profile and a direct content key from an independently selected
  baseline route; and
- chain selection at the issuer's current coordinate cannot jump to an older
  disconnected window merely because that window contains the item wrap; and
- a denied reader receives no usable capability under any authored supply
  form.

Detailed construction, geometry, bounds, malformed carriers and cache
strategies remain in the period-chain extension tests.

### `dca-v1-content-representations` with gzip

- Resolve baseline plus content-representations.
- Publisher gzip-compresses the selected item before encryption and sealing.
- Client authenticates and decrypts before applying gzip in reverse order.
- Original bytes and content type reach the presentation seam.
- A client without gzip refuses the marked item while an unencoded sibling can
  still open.
- Issuer behavior remains ordinary baseline behavior.

Malformed gzip and inflater corner cases remain in the content-compression
extension tests.

### Client-bound custody profiles

Run one complete scenario for each named alternative:

- `dca-v1-client-bound-ecdh-p256`; and
- `dca-v1-client-bound-rsa-oaep`.

Each covers the client offer, issuer selection, wrapped-leaf response,
non-extractable client custody, response admission and item opening. Required
client-bound mode must not silently return a direct key. Shared key validation
and malformed carriers remain in the extension's focused tests.

Track the current not-delivered identifier in the coverage index while its
classification remains unsettled. Do not add an executable canonical scenario
until the specification decides whether it remains a profile, becomes
universal core behavior or is removed.

## Useful composition coverage

Add or retain composition coverage only where specifications meet at a shared
wire or behavioral seam. The current audit considers:

- exact-period with each client-bound custody profile, because exact leaves
  change custody and response representation;
- period-chain with client-bound custody, covering both permitted exact-leaf
  projection and refusal of direct chain-state client-bound delivery;
- period-chain with content-key-seal omission, where omission makes the
  retained period route necessary;
- content representations with one non-direct key route, proving that key
  acquisition converges before authenticated content decoding; and
- browser-origin with a cached or client-specific path only where origin
  admission must precede that protected work.

Tests requiring two implementation extensions remain in `test-extensions/`.
This directory's coverage index points to them instead of copying them.

## Coverage index

For every named profile, record resolved dependencies, its canonical profile
test, any additional material scenario, focused supporting suites, relevant
extension compositions, status (`missing`, `partial` or `covered`) and the
evidence revision last assessed.

The rows below describe the current public tree. An immutable publication
commit pins the source and evidence revision together.

- `dca-v1-direct-https`
  - Dependencies: none beyond the baseline itself.
  - Canonical file: not yet extracted.
  - Interim complete scenario:
    [`test/sealer-direct-only.test.js`](../test/sealer-direct-only.test.js).
  - Focused supporting suites:
    [`test/dca-request-builder.test.js`](../test/dca-request-builder.test.js),
    [`test/issuer-ordinary-baseline.test.js`](../test/issuer-ordinary-baseline.test.js)
    and [`test/open-content.test.js`](../test/open-content.test.js).
  - Relevant extension compositions: none; optional profiles own the crossings
    they add to the baseline.
  - Status: **covered**; no optional period, transform, origin or client-bound
    path participates.
- `dca-v1-browser-origin`
  - Dependencies: `dca-v1-direct-https`.
  - Canonical file: not yet extracted.
  - Interim complete scenario:
    [`test/browser-origin-boundary.test.js`](../test/browser-origin-boundary.test.js).
  - Focused supporting suites:
    [`test-reference/core-publisher/sealer-origin.test.js`](../test-reference/core-publisher/sealer-origin.test.js),
    [`test-reference/core-shared/publisher-origin.test.js`](../test-reference/core-shared/publisher-origin.test.js)
    and [`test/endpoint-admission.test.js`](../test/endpoint-admission.test.js).
  - Relevant extension compositions: the interim scenario itself covers
    response-cache and fallback ordering; no separate extension composition is
    indexed.
  - Status: **covered**; focused publisher and adapter tests own individual
    origin spellings and HTTP behavior.
- `dca-v1-exact-period`
  - Dependencies: `dca-v1-direct-https`.
  - Canonical file:
    [`dca-v1-exact-period.test.js`](dca-v1-exact-period.test.js).
  - Focused supporting suites:
    [`test/exact-period-key-supply.test.js`](../test/exact-period-key-supply.test.js),
    [`test/dca-request-builder.test.js`](../test/dca-request-builder.test.js)
    and [`test/period-prefix.test.js`](../test/period-prefix.test.js).
  - Relevant extension compositions: the client-bound transport suite covers
    exact leaves with both
    [ECDH P-256 and RSA-OAEP](../extensions/client-bound-transport/test/client-bound.test.js),
    while
    [`test-extensions/client-bound-omission.test.js`](../test-extensions/client-bound-omission.test.js)
    covers an exact handle at the omission seam.
  - Status: **covered**; the canonical scenario proves successful delivery,
    retained-leaf reuse, issuer-selection refusal and entitlement denial. The
    focused request and issuer suites prove that carried exact material stays
    inactive when its trusted selection is off.
- `dca-period-chain-v1`
  - Dependencies: `dca-v1-direct-https`, `dca-v1-exact-period`.
  - Canonical file: missing.
  - Interim evidence:
    [`request-relay.test.js`](../extensions/period-chain/test/request-relay.test.js),
    [issuer result](../extensions/period-chain/test/issuer-chain-representation.test.js),
    and the period-chain composition tests under `test-extensions/`.
  - Focused supporting suites:
    [`construction-profiles.test.js`](../extensions/period-chain/test/construction-profiles.test.js),
    [`client-chain-cache.test.js`](../extensions/period-chain/test/client-chain-cache.test.js)
    and
    [`period-family-supply.test.js`](../extensions/period-chain/test/period-family-supply.test.js).
  - Relevant extension compositions:
    [`test-extensions/client-bound-period-chain.test.js`](../test-extensions/client-bound-period-chain.test.js),
    [`test-extensions/client-bound-period-chain-admission.test.js`](../test-extensions/client-bound-period-chain-admission.test.js)
    and the
    [period-chain/omission output crossing](../test-extensions/period-chain-omission-outputs.test.js).
  - Status: **partial**; the gaps below still lack one complete named scenario.
- `dca-v1-content-representations`
  - Dependencies: `dca-v1-direct-https`.
  - Canonical file: missing.
  - Focused publisher/client transform evidence:
    [`render-round-trip.test.js`](../extensions/content-compression/test/render-round-trip.test.js).
    This uses a local key resolver and does not cross a request or issuer seam.
  - Focused supporting suites:
    [`gzip-codec.test.js`](../extensions/content-compression/test/gzip-codec.test.js),
    [`open-encoded-content.test.js`](../extensions/content-compression/test/open-encoded-content.test.js)
    and
    [`base-client-cost.test.js`](../extensions/content-compression/test/base-client-cost.test.js).
  - Relevant extension compositions: none yet; a complete non-direct key-route
    crossing remains a gap.
  - Status: **partial**; baseline plus gzip is covered, while a non-direct key
    route remains unproved.
- `dca-v1-client-bound-ecdh-p256`
  - Dependencies: `dca-v1-direct-https`.
  - Canonical file: missing.
  - Interim complete scenario:
    [`browser-scenario.test.js`](../extensions/client-bound-transport/test/browser-scenario.test.js).
  - Focused supporting suites:
    [`client-bound-ec.test.js`](../extensions/client-bound-transport/test/client-bound-ec.test.js),
    [`client-bound-profiles.test.js`](../extensions/client-bound-transport/test/client-bound-profiles.test.js)
    and
    [`key-delivery.test.js`](../extensions/client-bound-transport/test/key-delivery.test.js).
  - Relevant extension compositions:
    [`test-extensions/client-bound-period-chain.test.js`](../test-extensions/client-bound-period-chain.test.js)
    and
    [`test-extensions/client-bound-omission.test.js`](../test-extensions/client-bound-omission.test.js).
  - Status: **covered**; focused client-bound and composition suites own the
    alternative custody and incompatibility rules.
- `dca-v1-client-bound-rsa-oaep`
  - Dependencies: `dca-v1-direct-https`.
  - Canonical file: missing.
  - Interim complete scenario:
    [`client-bound.test.js`](../extensions/client-bound-transport/test/client-bound.test.js).
  - Focused supporting suites:
    [`client-bound-profiles.test.js`](../extensions/client-bound-transport/test/client-bound-profiles.test.js)
    and
    [`key-delivery.test.js`](../extensions/client-bound-transport/test/key-delivery.test.js).
  - Relevant extension compositions: no RSA-specific cross-extension scenario
    is indexed; the interim scenario itself crosses request, issuer response,
    client custody and item opening.
  - Status: **covered**; the shared profile suite checks both supported
    client-bound methods.
- `dca-v1-not-delivered-result`
  - Dependencies: `dca-v1-direct-https` while the identifier remains in the
    profile specification.
  - Canonical file: missing.
  - Focused supporting suites: none while the profile classification remains
    unsettled.
  - Relevant extension compositions: none.
  - Status: **missing and blocked**; the specification may retain the
    profile, fold the behavior into core or remove the member.

The remaining consequential gaps are:

- compression has no chain-derived or cached-period complete scenario;
- disconnected-window delegation completeness lacks a focused pin;
- issuer suppression of chain output for a non-selecting client is only partly
  covered;
- exact and chain publisher supply reaching an exact-only issuer is only partly
  covered; and
- the explicit prohibition on two client-bound methods in one response lacks
  a focused test; and
- a rejected document-wide `accessGroups` geometry map needs a focused test
  that no dependent family recovers geometry from it.

This index maps evidence; it does not become another normative profile
catalogue. When the checked catalogue and verification claim index exist,
generate or validate dependency and evidence references from those owners.

## Tests that do not add useful profile evidence

Do not add:

- every permutation of profiles that operate on independent seams;
- baseline-plus-leaf combinations already implied by dependency resolution;
- exact-period plus period-chain as though the dependency were an independent
  pair of optional leaves;
- ECDH and RSA client-bound custody selected together, because they are
  alternative profiles;
- gzip repeated with every issuer envelope, key-delivery form or cache policy
  after those paths converge on the same content-opening seam;
- browser-origin repeated with every optional profile when one test already
  proves that origin admission precedes policy, cache and opening-key work;
- the same complete scenario with irrelevant issuer counts, time values,
  geometries or algorithm choices;
- malformed inputs, bounds and crypto vectors already owned by focused unit or
  recorded-vector suites;
- wrappers that merely run or import existing test files;
- scenarios made green by test support that reimplements the publisher,
  issuer, client, parser, crypto or policy behavior under test;
- assertions that only find a field without proving its selection, admission
  and observable effect;
- an implementation extension treated as a named protocol profile; or
- a new scenario whose only distinction cannot change bytes, role duties,
  security behavior, fallback or the final reader outcome.
