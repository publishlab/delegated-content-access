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
dca-profile-baseline.test.js
dca-profile-browser-origin.test.js
dca-profile-html-carrier.test.js
dca-profile-period-keys.test.js
dca-profile-chain-keys.test.js
dca-profile-content-compression.test.js
dca-profile-client-bound-ecdh-p256.test.js
dca-profile-client-bound-rsa-oaep.test.js
dca-profile-recipient-grant-unlock.test.js
dca-profile-content-groups.test.js
```

The baseline, HTML carrier, period-key, chain-key, content-compression,
recipient-grant-unlock and content-groups files exist today. For the remaining target files, the
coverage index below names focused interim evidence rather than pretending the
target filename exists.

Join two independent requested leaves with `--` only when their shared seam
requires a complete scenario that neither leaf establishes alone.

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
chain-key scenario resolves the baseline and period-key profiles before
the chain-key profile. Baseline plus period-key is therefore not another
chain-key combination.

Test a set of independent leaves only when they meet at a shared seam or an
authority defines a joint rule. Do not enumerate the Cartesian product. A
single representative combination is enough when several key-delivery forms
converge on the same authenticated content-opening seam.

For chain keys, useful distinctions include chain input projected to period
keys for a client that accepts only period keys, chain input returned as chain
keys to a chain-aware client, and period-key plus chain-key publisher supply
where presence does not force chain use. Item content-key delivery remains an
independent baseline alternative. One response may carry period keys for one
family and chain keys for another. On a chain-owned route one family returns
period keys or chain keys, not both; an explicitly configured
period-key-and-chain-key input union does not change that response rule.

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
the host's [trusted route configuration](../../docs/guide--unlock-fallback.md#why-routing-does-not-belong-in-publisher-data).

The issuer has the corresponding trusted selection for the input and output
forms it processes. A baseline-only issuer ignores optional period-key and
chain-key sections rather than parsing them. A period-key issuer may process
selected period-key input. A chain-key issuer may process selected chain input
and may project period keys or, for a selecting client, return chain keys.

The initial selection scenarios establish that:

- a baseline-only client uses a complete item content-key route and does not
  relay period keys or chain keys merely because the delivery carries them;
- unselected optional material, including malformed profile-local coordinates,
  does not gain parsing or route meaning beside that usable item content-key
  route, subject to the protocol's outer resource limits;
- a period-key client may select period keys without selecting chain keys;
- a chain-key client resolves period-key support but still chooses period-key,
  chain-key or both authored request routes explicitly;
- the presence of both period keys and chain keys does not automatically select
  either or both; and
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

### `dca-profile-baseline`

- Resolve the baseline alone.
- Publisher produces one protected item, assertion and item content-key route
  and writes the delivery as the serialized UTF-8 JSON document of
  [data format Section 6](../../docs/spec--data-format.md); the client
  reads that document, not a language-native object.
- Issuer verifies, authorizes and returns an item content key through the
  ordinary HTTPS JSON response shape.
- Client associates the response and opens the item.
- Period-key, compression, browser-origin and client-bound behavior is absent.

### `dca-profile-browser-origin`

- Resolve baseline plus browser-origin.
- Publisher signs the delivery origin, the browser boundary supplies it, and
  the issuer admits the exact match before protected work.
- A mismatching observed origin reaches no policy, cache or opening key.
- Keep credentialed-mode permutations in focused tests unless they change
  another crossing.

### `dca-profile-period-keys`

- Resolve baseline plus period-key.
- Publisher authors period-key wraps and matching issuer capability.
- Request relays an unresolved period-key coordinate; issuer returns an
  authorized period key; client files it and opens the item.
- A second item in the same period opens from the retained period key without
  another issuer call.
- No chain key participates.

The canonical scenario is
[`dca-profile-period-keys.test.js`](dca-profile-period-keys.test.js). It disables the
publisher's item content-key route, selects period-key relay and issuer input
independently, opens the first item through the returned period key, and opens
a second item from retained capability without another issuer call. The focused
request and issuer suites separately prove that carried period keys stay
inactive when the applicable selection is off.

### `dca-profile-chain-keys`

Resolve baseline, period-key and chain-key. Exercise two complete forms
because issuer output changes downstream role requirements:

1. Publisher supplies chain keys only, the request relays them, the issuer
   projects period keys, and a client that accepts only period keys opens the
   item.
2. Publisher supplies chain keys only, the issuer returns positioned chain
   keys, and a chain-aware client derives the period key and opens the item.

Also establish that:

- period-key plus chain-key publisher supply does not force the issuer to use
  chain keys;
- a relied-on chain-only route cannot silently use omitted publisher-to-issuer
  period keys;
- an independently authored item content-key route remains usable;
- an issuer does not return chain keys to a client that did not select them; and
- a chain-capable client still accepts a period-key result inherited through the
  dependency profile and an item content key from an independently selected
  baseline route; and
- chain selection at the issuer's current coordinate cannot jump to an older
  disconnected window merely because that window contains the item wrap; and
- a denied reader receives no usable capability under any authored supply
  form.

Detailed construction, geometry, bounds, malformed carriers and cache
strategies remain in the chain-key extension tests.

### `dca-profile-content-compression`

- Resolve baseline plus content-compression.
- Publisher gzip-compresses the selected item before encryption and sealing
  and declares `["gzip"]`.
- Client authenticates and decrypts before it decodes gzip.
- Original bytes and content type reach the presentation seam.
- A client without gzip refuses the marked item while an unencoded sibling can
  still open.
- Issuer behavior remains ordinary baseline behavior.

Malformed gzip and inflater corner cases remain in the content-compression
extension tests.

### Client-bound custody profiles

Run one complete scenario for each named alternative:

- `dca-profile-client-bound-ecdh-p256`; and
- `dca-profile-client-bound-rsa-oaep`.

Each covers the client offer, issuer selection, wrapped-key response,
non-extractable client custody, response admission and item opening. Required
client-bound mode must not silently return direct bytes. Shared key validation
and malformed carriers remain in the extension's focused tests.

### `dca-profile-recipient-grant-unlock`

- Resolve baseline plus recipient-grant unlock; a browser caller also resolves
  browser-origin.
- The trusted host sends one bearer to the selected issuer; the issuer admits
  it and the client opens the item, then again on a later render that changes
  the item under the same granted name.
- A wrong issuer, publisher, resource or name, an expired or revoked grant and
  an unpresented coordinate each yield no key.
- The client refuses a result that carries period keys or chain keys.

The [binding's conformance boundary](../../docs/spec-profile--recipient-grant-unlock.md#6-conformance-boundary)
lists these cases.

### `dca-profile-html-carrier`

- Resolve baseline plus HTML carrier.
- Publisher emits the delivery as reserved inert JSON `script` elements in
  markup; client extracts the same members from that markup.
- Every step after extraction, and the issuer, stays the baseline's.
- Browser-origin admission is neither selected nor required.

## Useful composition coverage

Add or retain composition coverage only where specifications meet at a shared
wire or behavioral seam. The current audit considers:

- period-key with each client-bound custody profile, because period keys
  change custody and response representation;
- chain-key with client-bound custody, covering period-key projection and
  admitted chain-key delivery under both client-bound methods;
- chain-key with content-key-seal omission, where omission makes the
  retained period route necessary;
- content compression with one key route other than item content-key
  delivery, proving that key acquisition converges before authenticated content
  decoding; and
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

Each entry's dependencies are the profile's own closure. The carrier a
scenario runs is a separate fact:

- Only [`dca-profile-baseline.test.js`](dca-profile-baseline.test.js) crosses the
  serialized JSON document.
- The period-key, chain-key and content-compression scenarios drive the demo
  browser. It reads each delivery with `MarkupDeliveryReader` over fabricated
  carrier elements, so the closure those scenarios run also holds
  `dca-profile-html-carrier`. Their tags and claim records name only their own key
  and representation duties.
- The content-map candidate scenario writes and extracts real markup. That
  records what ran; the candidate's dependency on `dca-profile-html-carrier` is
  undecided.

The profile entries:

- `dca-profile-baseline`
  - Dependencies: none beyond the baseline itself.
  - Canonical file:
    [`dca-profile-baseline.test.js`](dca-profile-baseline.test.js) crosses the
    serialized JSON document from publisher to client, with the issuer
    answering the request built from it.
  - Other evidence:
    [`test-reference/core-publisher/sealer-content-key-only.test.js`](../test-reference/core-publisher/sealer-content-key-only.test.js)
    seals and opens through markup, so its markup scenarios also carry the
    `dca-profile-html-carrier` tags.
  - Focused supporting suites:
    [`test-reference/core-client/dca-request-builder.test.js`](../test-reference/core-client/dca-request-builder.test.js),
    [`test-reference/core-issuer/issuer-ordinary-baseline.test.js`](../test-reference/core-issuer/issuer-ordinary-baseline.test.js)
    and [`test-reference/core-client/open-content.test.js`](../test-reference/core-client/open-content.test.js).
    The generic representation opener tests in
    [`wire-lookup-client.test.js`](../test-reference/core-client/wire-lookup-client.test.js)
    use stand-in decoders for layer order, repetitions, list refusal before
    key resolution, decoder failure and authentication before decoding.
  - Relevant extension compositions: none; optional profiles own the crossings
    they add to the baseline.
  - Status: **partial**; no optional period, transform, origin or client-bound
    path participates, and the reference path enforces no generic
    layer-count, name-size, decoded-output or decoding-work limit.
- `dca-profile-browser-origin`
  - Dependencies: `dca-profile-baseline`.
  - Canonical file: not yet extracted.
  - Interim complete scenario:
    [`test/browser-origin-boundary.test.js`](../test/browser-origin-boundary.test.js).
  - Focused supporting suites:
    [`test-reference/core-publisher/sealer-origin.test.js`](../test-reference/core-publisher/sealer-origin.test.js),
    [`test-reference/core-shared/publisher-origin.test.js`](../test-reference/core-shared/publisher-origin.test.js)
    and [`test-reference/core-issuer/endpoint-admission.test.js`](../test-reference/core-issuer/endpoint-admission.test.js).
  - Relevant extension compositions: the interim scenario itself covers
    policy, opening-key and fallback-probe ordering; no separate extension
    composition is indexed.
  - Status: **covered**; focused publisher and adapter tests own individual
    origin spellings and HTTP behavior.
- `dca-profile-period-keys`
  - Dependencies: `dca-profile-baseline`.
  - Canonical file:
    [`dca-profile-period-keys.test.js`](dca-profile-period-keys.test.js).
  - Focused supporting suites:
    [`test-reference/demo-support/random-period-key-supply.test.js`](../test-reference/demo-support/random-period-key-supply.test.js),
    [`test-reference/core-client/dca-request-builder.test.js`](../test-reference/core-client/dca-request-builder.test.js)
    and [`test-reference/core-issuer/period-label-grants.test.js`](../test-reference/core-issuer/period-label-grants.test.js).
  - Relevant extension compositions: the client-bound transport suite covers
    period keys with both
    [ECDH P-256 and RSA-OAEP](../extensions/client-bound-transport/test/client-bound.test.js),
    while
    [`test-extensions/client-bound-omission.test.js`](../test-extensions/client-bound-omission.test.js)
    covers a period-key handle at the omission seam.
  - Status: **covered**; the canonical scenario proves successful delivery,
    retained-period-key reuse, issuer-selection refusal and entitlement
    denial. The focused request and issuer suites prove that carried period
    keys stay inactive when their trusted selection is off.
- `dca-profile-chain-keys`
  - Dependencies: `dca-profile-baseline`, `dca-profile-period-keys`.
  - Canonical file:
    [`dca-profile-chain-keys.test.js`](dca-profile-chain-keys.test.js) crosses
    publisher chain-only supply, selected request relay and issuer input,
    then either period-key projection to a relay-only client or positioned
    chain-key output and client period-key derivation. Both open the authored
    item, and the period-key-only response carries no chain key. A third
    scenario supplies period-key and chain-key members of one family
    generation to an issuer that selected period-key input only. The client
    relays both forms and accepts period-key results only, the issuer answers
    from the period-key members with no chain key, the item opens, and a
    reader the issuer's policy denies receives no capability although the
    request carried both forms. A fourth scenario
    deliberately mismatches the issuer's chain-output configuration with a
    relay-only client: it observes a real positioned chain result, then proves
    the client rejects it without retaining a key or opening the item.
    The chain-key prefix scenario then opens every item from one window start
    through its cutoff from one retained key and one issuer exchange; later
    same-window and adjacent-window items remain unopened from that retained
    key, without a new grant. With zero future count, the issuer independently
    authorizes the requested article target and every position of its
    ten-position backward prefix. Chain-output
    configuration selects response form and never authorizes that reach.
    Live refusal cases deny a policy that authorizes no period before key-store
    lookup and reject missing/mismatched response geometry or an unpresented window,
    retain nothing, then open successfully after a valid response.
    The [recorded prefix replay](../test-vectors/chain-keys-prefix.test.js)
    exercises the issuer/client path from signed publisher inputs; it does
    not replay the publisher or those live refusal cases.
  - Other evidence:
    [`request-relay.test.js`](../extensions/chain-keys/test/request-relay.test.js),
    [issuer result](../extensions/chain-keys/test/issuer-chain-representation.test.js),
    and the chain-key composition tests under `test-extensions/`.
  - Focused supporting suites:
    [`construction-profiles.test.js`](../extensions/chain-keys/test/construction-profiles.test.js),
    [`client-chain-cache.test.js`](../extensions/chain-keys/test/client-chain-cache.test.js),
    and
    [`period-family-supply.test.js`](../extensions/chain-keys/test/period-family-supply.test.js).
    [`chain-key-rejections.test.js`](../extensions/chain-keys/test/chain-key-rejections.test.js)
    covers a present malformed document-wide `accessGroups` map: the client
    relays it unchanged, and request and response admission leave the
    supplied family invalid beside a valid document pair.
    [`issuer-chain-gap-content-key-route.test.js`](../extensions/chain-keys/test/issuer-chain-gap-content-key-route.test.js)
    covers current-window selection, disconnected-window refusal, and
    same-window backward reach.
  - Relevant extension compositions:
    [`test-extensions/client-bound-chain-keys.test.js`](../test-extensions/client-bound-chain-keys.test.js),
    [`test-extensions/client-bound-chain-keys-admission.test.js`](../test-extensions/client-bound-chain-keys-admission.test.js)
    and the
    [chain-key/omission output crossing](../test-extensions/chain-keys-omission-outputs.test.js).
  - Status: **covered**; complete named scenarios exercise both chain-input
    response forms, period-key-plus-chain-key supply at an issuer that takes
    only period keys, and client refusal when a misconfigured issuer returns
    chain keys to a client without chain acceptance, and complete prefix use
    plus out-of-reach, grant and response-admission refusal for one selected
    geometry/window/cutoff.
    These scenario results and their recorded issuer/client replay remain
    bounded JavaScript evidence; the claim index still marks every pilot
    incomplete. Focused suites own the other selection and denial cases.
- `dca-profile-content-compression`
  - Dependencies: `dca-profile-baseline`.
  - Canonical file:
    [`dca-profile-content-compression.test.js`](dca-profile-content-compression.test.js)
    also requests `dca-profile-period-keys` for the key route. The publisher
    gzip-compresses before sealing and authors no item content-key route,
    the issuer returns period keys and no content key, and the client
    decrypts under the content key it unwraps with the returned period key
    before gzip restores the article. A second article in the same period
    opens from the retained period key without another issuer call.
  - Focused publisher/client transform evidence:
    [`render-round-trip.test.js`](../extensions/content-compression/test/render-round-trip.test.js).
    This uses a local key resolver and does not cross a request or issuer seam.
  - Focused supporting suites:
    [`gzip-codec.test.js`](../extensions/content-compression/test/gzip-codec.test.js),
    [`open-encoded-content.test.js`](../extensions/content-compression/test/open-encoded-content.test.js),
    and
    [`base-client-cost.test.js`](../extensions/content-compression/test/base-client-cost.test.js)
    for a client without gzip refusing only the marked item.
  - Relevant extension compositions: none; the canonical file covers the
    period-key route, and other key-delivery forms converge on the same
    content-opening seam.
  - Status: **partial**; compression before sealing and decryption before
    gzip decoding run through the period-key route, with retained period-key
    reuse. The prototype gzip paths do not establish the strict one-member
    contract or hard resource bounds: the native Web Streams path accepts
    concatenated members.
- `dca-profile-client-bound-ecdh-p256`
  - Dependencies: `dca-profile-baseline`.
  - Canonical file: missing.
  - Interim complete scenario:
    [`browser-scenario.test.js`](../extensions/client-bound-transport/test/browser-scenario.test.js).
  - Focused supporting suites:
    [`client-bound-ec.test.js`](../extensions/client-bound-transport/test/client-bound-ec.test.js),
    [`client-bound-profiles.test.js`](../extensions/client-bound-transport/test/client-bound-profiles.test.js)
    and
    [`key-delivery.test.js`](../extensions/client-bound-transport/test/key-delivery.test.js).
  - Relevant extension compositions:
    [`test-extensions/client-bound-chain-keys.test.js`](../test-extensions/client-bound-chain-keys.test.js),
    [`test-extensions/client-bound-chain-keys-admission.test.js`](../test-extensions/client-bound-chain-keys-admission.test.js)
    and
    [`test-extensions/client-bound-omission.test.js`](../test-extensions/client-bound-omission.test.js).
  - Status: **covered**; focused client-bound and composition suites own the
    alternative custody and incompatibility rules.
- `dca-profile-client-bound-rsa-oaep`
  - Dependencies: `dca-profile-baseline`.
  - Canonical file: missing.
  - Interim complete scenario:
    [`client-bound.test.js`](../extensions/client-bound-transport/test/client-bound.test.js).
  - Focused supporting suites:
    [`client-bound-profiles.test.js`](../extensions/client-bound-transport/test/client-bound-profiles.test.js)
    and
    [`key-delivery.test.js`](../extensions/client-bound-transport/test/key-delivery.test.js).
  - Relevant extension composition:
    [`test-extensions/client-bound-chain-keys-admission.test.js`](../test-extensions/client-bound-chain-keys-admission.test.js)
    covers RSA chain-key delivery, admission, derived period key and item opening.
  - Status: **covered**; the shared profile suite checks both supported
    client-bound methods.
- `dca-profile-recipient-grant-unlock`
  - Dependencies: `dca-profile-baseline`; a browser caller also requests
    `dca-profile-browser-origin`.
  - Canonical file:
    [`dca-profile-recipient-grant-unlock.test.js`](dca-profile-recipient-grant-unlock.test.js).
    A browser client sends one bearer in `Authorization` to the trusted
    issuer, with `credentials: "omit"`, `redirect: "error"`, only
    `sealed.contentKeys` and no bearer in the body. It opens the item on two
    renders, the second changing the item under the same granted name, and
    gets no key for an ungranted or new name. A second scenario has the
    issuer refuse a revoked grant, then an independently selected ordinary
    login opens the item without replaying the bearer.
  - Focused supporting suites:
    [`signedGrant.test.js`](../extensions/recipient-grant/test/signedGrant.test.js)
    proves ES256 minting, optional HS256, trusted key and audience admission,
    upstream reader-gift authorization, two independently provisioned issuer
    routes and original-byte opening from one unchanged token;
    [`browserHost.test.js`](../extensions/recipient-grant/test/browserHost.test.js)
    proves query and injected carriage, ordinary-access skip, retention and
    pending-attempt retirement;
    [`issuer.test.js`](../extensions/recipient-grant/test/issuer.test.js)
    for admission before grant lookup, wrong issuer, publisher, resource,
    time and revocation, name and policy intersection, and period-input
    refusal;
    [`client.test.js`](../extensions/recipient-grant/test/client.test.js)
    for refusal of period or chain results, unpresented items, redirects and
    trusted endpoint selection.
  - Relevant extension compositions:
    [`test-extensions/recipient-grant-compact-ecdh.test.js`](../test-extensions/recipient-grant-compact-ecdh.test.js)
    opens the granted item through one key entry that permits ordinary and compact
    ECDH, on an ordinary and on a compact-selected render. No test yet composes a
    recipient grant with client-bound custody.
  - Status: **JS reference evidence covered** for the signed direct-bearer
    flow. The canonical profile scenario still exercises the optional opaque
    form; the signed extension composition supplies the common signed proof.
    Product PHP, issuer session exchange and a native browser deployment are
    outside this evidence.
- `dca-profile-html-carrier`
  - Dependencies: `dca-profile-baseline`.
  - Canonical file:
    [`dca-profile-html-carrier.test.js`](dca-profile-html-carrier.test.js) selects the
    HTML carrier, writes markup and extracts the delivery from it.
  - Other evidence: the markup scenarios in
    [`sealer-content-key-only.test.js`](../test-reference/core-publisher/sealer-content-key-only.test.js)
    and the markup-to-browser-entry unlock in
    [`createBrowserClient.test.js`](../test-reference/integration-client/createBrowserClient.test.js).
  - Focused supporting suites:
    [`markup-writer.test.js`](../test-reference/adapter-publisher/markup-writer.test.js)
    and
    [`markup-delivery-reader.test.js`](../test-reference/adapter-client/markup-delivery-reader.test.js).
  - Relevant extension compositions: none.
  - Status: **partial**; reference JavaScript only. The client reads a
    simulated root, a regex scan over the markup string, so no real HTML
    parser or browser runs in the base suite. The `html-carrier-in-simulated-dom`
    scenario records this evidence and stays incomplete.
- `dca-profile-content-groups` (proposed)
  - Dependencies: `dca-profile-baseline`. The stock chain-key derivation is the
    host's trusted chain port; it does not select `dca-profile-chain-keys`.
  - Canonical file:
    [`dca-profile-content-groups.test.js`](dca-profile-content-groups.test.js)
    answers fixed vectors that
    [`generate-production-vectors.mjs`](../extensions/content-groups/test/_lib/generate-production-vectors.mjs)
    wrote from `node:crypto` and the specifications: the issuer opens the fixed
    seed envelopes and answers the fixed request with the fixed response, and
    the composed client builds that request and opens a chain-key, a period-key
    and an item-key item.
  - Focused supporting suites: the extension's own tests under
    [`extensions/content-groups/test/`](../extensions/content-groups/test/).
  - Relevant extension compositions:
    [`content-groups-composition.test.js`](../test-extensions/content-groups-composition.test.js)
    composes the chain-keys cache and both client-bound methods over JSON and
    HTML carriers, with denials, substitutions, storage and reset. It also puts
    content groups beside compression and beside a compact-selected issuer, and
    composes chain keys with content groups in one base issuer engine.
  - Status: **partial**; reference JavaScript only, no claim tags, and the
    profile catalogue names no content-groups entry yet.

The two-method exclusion needs no additional profile scenario. A request
offers one method through one `clientPublicKey`, and a response confirms one
method through one `transport.method`; a valid response cannot select both.
The [resolver admission test](../test-reference/core-client/content-key-resolver.test.js)
offers RSA-OAEP and receives ECDH-P256, then observes `invalid_transport`
before any opener runs or content key is retained. The same test checks an
absent offer and an immutable offer snapshot. The focused client-bound suites
above cover each selected method's successful path.

This index maps JavaScript reference evidence; it does not become another
normative profile catalogue. Named profiles and dependencies are checked by
[`verification/profile-catalogue/v1.json`](../../verification/profile-catalogue/v1.json).
The current [scoped profile evidence index](../../verification/claim-index/README.md)
records exact JavaScript test identities and selections for eight deliberately
incomplete scenarios. `baseline-json-direct` crosses the serialized JSON
document, and `html-carrier-in-simulated-dom` uses the markup reader through a
simulated root. Neither report implies browser or complete profile conformance.

## Tests that do not add useful profile evidence

Do not add:

- every permutation of profiles that operate on independent seams;
- baseline-plus-leaf combinations already implied by dependency resolution;
- period-key plus chain-key as though the dependency were an independent
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
