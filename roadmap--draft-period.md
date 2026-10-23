# Public draft-period roadmap

Status: Informative Draft

The current [specifications and document status](docs/spec---overview.md#document-status)
define DCA's requirements. This roadmap lists remaining design, implementation
and evidence work that may affect a public working draft. Each specification,
proposal and profile retains its stated status. The listed work does not wait for a publication.

## Which document to use

- **Starting now:** follow the [specification overview](docs/spec---overview.md#start-here)
  and the one-item baseline example. Add optional profiles only for capabilities
  your deployment needs.
- **Updating an implementation:** read [CHANGELOG.md](CHANGELOG.md) against the
  exact draft revision you implemented. It identifies breaking changes and the
  publisher, issuer and client updates they need. Matching wire version `"1"`
  alone does not establish compatibility between drafts.
- **Evaluating future work:** use this roadmap. Implemented reference code does
  not adopt a Proposal or establish interoperability with an existing vendor
  integration. Each specification's stated status remains authoritative.

A content key encrypts one item. Optional period keys let a client reuse access
across matching content; optional chains compact the delivery of those period
capabilities. The [period-key worked example](docs/guide--integration--period-keys.md#the-result-to-preserve)
shows the publisher, issuer and client path. The current baseline requires
content-key support; period keys and chains remain optional.

## Next priorities

1. **Settle the minimum reusable-key support.** The current baseline uses
   content keys; period-key support is optional. The design
   direction under consideration is to require both content-key and period-key
   support while keeping chains optional. Decide this before changing the
   baseline claim, then align specifications, reference behavior and evidence.
   Required support would not force every article to carry both routes or
   require an issuer to grant reusable keys. Record the extra burden on each
   role and the resulting interoperability guarantee. Compare the proposed
   content-group seed/connector construction as another baseline candidate;
   its implementation as an extension does not settle that choice.
2. **Publish examples that match the actual capabilities.** Show simple random
   pkeys, publisher-first chain activation while supplying the ordinary pkeys needed by
   the selected routes, and
   issuer chain input with either pkey or chain output. Include forward-overlap
   rollover without a second transmitted chain. State what each role must support and
   avoid claiming that the current-format activation tests establish
   interoperability with the September chain format.

These are work priorities, not announced changes or a publication date. A
baseline change requires a separate adoption decision and compatibility notes.
Each publication records a snapshot of reviewed work. Protocol changes follow
the [specification adoption process](docs/spec---overview.md#document-status). The [profile specification](docs/spec--profiles.md) remains the
source of current mandatory and optional duties.

## Current reference capabilities

Publication-by-publication compatibility notes are recorded in
[CHANGELOG.md](CHANGELOG.md). Its Unreleased section covers changes since
v1.0.0-alpha.2, published on 20 October 2026.

**Current draft compatibility:** unreleased deliveries and exchanges use arrays
of named records, 97-octet ordinary ECDH key envelopes and 113-octet content-group
seed envelopes. They are incompatible with the former maps and carried-nonce
envelopes. The changelog identifies the roles that must update together and the
selected-profile boundaries. These changes and the reference corrections remain
Unreleased until a publication records them; they are not evidence of native-port
or deployed-browser compatibility.

**Chain activation and period-key overlap:** a simple publisher can keep random
pkeys without chain construction. Enabling chains selects a new generation of derived pkeys. Compatible clients
obtain them through an ordinary unlock and can retain old keys for old pages.
Supplying both ordinary pkeys and chains lets the relay and issuer enable
chain handling later using the same saved article. An issuer may consume chains
and return ordinary pkeys; chain output separately requires a capable client.

The publisher derives the same bytes for the forward overlap pkey when its
period becomes current. One
current-window chain plus an ordinary overlap-period source is sufficient;
another chain entry is not required merely for overlap. A cached-only overlap
wrap is also valid when another selected issuer route already completes the item. These paths have executable
activation, retained-key, rollover and cutoff evidence in
`js/extensions/chain-keys/test/`. See the
[chain-key guide](docs/guide--chain-keys.md#starting-with-period-keys-and-enabling-chains-later).

**Shared period geometry:** period authoring now carries one top-level
`periodGeometry` with `periodMinutes`; selected chain processing adds
`chainsPerDay`. All ordinary and content-group chain routes in one delivery
share that pair. Ordinary pkey labels stay explicit, including overlap or
next-period wraps. The content-groups Proposal uses root `renderPeriod` and per-item named
`connectors`; `contentGroupKeys` names its response section, not a delivery-root
group dictionary. Its secret-rotation candidates require bounded rival trials,
while retention duration remains an integration choice.

**Compact ECDH envelopes:** the optional
[compact ECDH profile](docs/spec-profile--compact-ecdh.md) and its
[reference extension](js/extensions/compact-ecdh/README.md) provide the fixed
HPKE-compatible compressed-envelope path. Ordinary envelopes remain available.
Selection requires matching publisher, relay and issuer support and explicit
issuer key permissions; no runtime capability negotiation is implied.

**Content-groups reference integration:** the
[extension](js/extensions/content-groups/README.md) now composes the real
publisher, issuer and delivery client, with ordinary item-key coexistence,
persistent storage, reader reset and both client-bound response methods.
Construction, refusal and composition evidence live in its tests. The profile
remains a Proposal; reference integration does not select it as the baseline
or prove every combination of extensions.

## Remaining draft-period work

- **Protected HTML reconstruction** [optional profile, publication]
  - **Current state:** Publisher placement and bounded reconstruction code
    exist. The [content-description and placement document](docs/spec-proposal--content-description-and-placement.md)
    and [HTML content-map profile](docs/spec-proposal--html-content-map.md)
    remain Proposals; neither changes the required item `contentType` or makes
    a map a baseline requirement.
  - **Remaining work:** When selected, validate the format against representative
    customer templates and have the specification maintainers decide promotion.
    Preserve the
    publisher's chosen handler as the ordinary renderer; an independent map
    client remains an explicit alternative.
  - **Boundary:** This does not change issuer authorization, content-key
    formats or the baseline JSON delivery.

- **Browser deployment validation** [integration, product]
  - **Current state:** The browser-integration interfaces remain a proposal;
    the [independent-provider prototype](js/experiments/browser-integration/README.md#independent-provider-replacement-example) provides experimental evidence. It does not
    establish live vendor compatibility, production credentials or a deployed
    customer-page integration.
  - **Remaining work:** Have the integrating application owner validate a selected real integration,
    using its exact credential, ambient-cookie and completion/lifetime questions. Keep this separate from
    profile adoption and from the HTML-map reconstruction decision.
  - **Contract:** The [browser integration proposal](docs/spec-proposal--browser-integration.md)
    defines the candidate interface.

- **Content-key seal-omission adoption** [optional profile, wire]
  - **Current state:** The extension is classified as a non-adopted prototype.
    Its documentation describes the prototype's trust and admission boundaries.
    No interoperable profile for it has been adopted, and it adds no baseline
    requirement.
  - **Remaining work:** Decide whether to adopt an optional interoperable
    profile or retain the experiment. If adopted, define that profile through
    the existing extension and profile authority; do not reopen the prototype's
    support signal as a baseline mechanism.
  - **Design input:** [Seal-omission prototype](js/extensions/content-key-seal-omission/README.md).

- **Content groups with scoped seeds and connectors** [proposal, wire]
  - **Current state:** The [content-groups Proposal](docs/spec-profile--content-groups.md)
    has a reference extension integrated as described above. One seed covers
    one content name and window; named group chains lead through per-item
    connectors to content keys. The issuer authorizes an item and returns a
    candidate content key computed from its connector. A wrong candidate leaves
    the client unable to open the content; no signed key commitment is required.
  - **Remaining work:** Settle adoption and portability evidence, separately
    from whether this construction belongs in the baseline. Before advertising
    broader composition, prove a client using separate stock-chain and
    content-groups issuers. The stock injected chain-key engine cannot be combined
    with the content-groups contribution; a host-composed base engine can serve
    both. Compact-selected
    content-group seed blocks are not supported by this integration. See the
    [composition limits](js/extensions/content-groups/README.md#composition-contentgroupsprofile).
    Compare complete metadata and one unlock response against ordinary period
    keys plus chains with matching groups, time grants and cache assumptions.
  - **Tradeoff:** An entrusted issuer can derive every group for the supplied
    content name and window, across articles. It cannot derive withheld content
    names. Omitting it from a later article does not revoke the seed's existing
    reach. Narrower issuer entrustment needs a narrower supplied scope or source.

- **Issuer-response size reduction** [research, wire]
  - **Current state:** Ordinary ECDH key and content-group seed envelopes omit
    their transmitted nonce; issuer responses retain theirs.
  - **Remaining work:** Any response nonce omission needs a separately selected
    construction and interoperability evidence. It remains deferred; current
    coordinates alone do not distinguish rival keys at one coordinate.
  - **Boundary:** No response field or fixed-nonce procedure is introduced by
    the completed ordinary-envelope changes.

- **Access-group generalization** [design, profile]
  - **Current state:** Generalization remains paused;
    the October 12 baseline/naming steering is preserved without adoption.
    The current period-key and chain-key specifications continue to apply.
    Named sets are one candidate organization for the bounded
    OR model; no new wire fields, profile names or production provisioning
    rules are adopted.
  - **Remaining work:** Decide whether named sets need a wire representation or
    remain publisher/issuer configuration, and settle provisioning and
    combination semantics before any replacement specification is adopted.

- **Reducing multi-group delivery cost** [research, verification]
  - **Current state:** Ordinary pkeys plus optional chains remain the specified
    reusable path. Tree-node and subset-cover constructions are unpublished
    research constructions; neither is an adopted profile. Subset cover is a
    candidate for reducing both content-key wraps and returned chains when
    article memberships and authorized access fit configured complete subsets.
  - **Remaining work:** Compare singleton, aligned, scattered and all-group
    cases using the same article memberships, reader authorization, time grant
    and issuer-supply assumptions. Measure serialized DCA metadata separately
    from encrypted content, and one actual unlock response, as raw JSON and
    gzip. Verify that authorized content opens, unauthorized content stays
    closed, and cached capabilities behave as claimed before promotion.
  - **Tradeoffs to settle:** Configured combinations of groups may save bytes; a flat list of unrelated
    group names need not. Trees may reduce responses while adding links and
    tree descriptions to publisher metadata. Subset cover may leave the client
    without reusable keys for some later articles, requiring another unlock.
    Report metadata bytes, response bytes and additional unlocks separately from
    the time reach provided by chains.
  - **Reference authoring policy:** Selected chain supply defaults to one item
    wrap at the render period; `chainItemSlots` explicitly adds alternatives and
    `chainWindows` independently selects supply. Ordinary slots are unchanged.
    Real rollover/denial/cache/projection checks and the
    [saved byte comparison](js/evidence-benchmarks/chain-keys-wire-cost/README.md#t0-item-policy-saved-genuine-output)
    cover this choice. A next-window key alone cannot open an old-window wrap;
    old matching capability, authorized recovery or another complete route is
    still required. This changes no profile's required support.
  - **Boundary:** Preserve sparse article membership and request selection.
    No new group-set wire object, tree format or subset-cover profile follows
    from a size estimate alone.

- **Recipient-grant interoperability evidence** [optional profile, verification]
  - **Current state:** The [recipient-grant specification](docs/spec-profile--recipient-grant-unlock.md)
    defines an optional profile, with a JavaScript reference implementation.
    Shared recipient-profile conformance is not established.
  - **Confirmed gap:** The shared index has no recipient-grant scenario or
    support declaration. Existing signed-grant, issuer, client, browser-host
    and profile tests provide implementation evidence; the index gap does not
    establish a missing implementation test.
  - **Remaining work:** Compare that existing evidence with the specification's
    [Section 6 requirements](docs/spec-profile--recipient-grant-unlock.md#6-conformance-boundary),
    map it into the [evidence index](verification/claim-index/README.md), and
    identify any uncovered requirement explicitly before adding tests. No
    specific missing behavioral test has been established here.

- **Reference crypto-provider portability** [JavaScript, ports]
  - **Current state:** `js/core-shared/cryptoProvider.js` captures the host
    WebCrypto `subtle` object at module load. `js/PORTING.md` specifies
    operation and stable error-code behavior for ports, not a replaceable
    provider interface or English exception text.
  - **Remaining work:** Establish whether a supported reference-port use case
    needs provider injection. If so, define and test that reference API at the
    JavaScript boundary. This is not a protocol or wire-format requirement.

## Deployment work outside the protocol

The [recipient-grant specification](docs/spec-profile--recipient-grant-unlock.md)
defines the optional unlock contract for link sharing. Grant issuance services,
share UI, link carriage and storage are host deployment choices outside that
binding. The JavaScript reference provides implementation evidence; deployed
browser and issuer-session integration remain deployment work.

Publisher signing-key activation, overlap and retirement follow the
[core registration rules](docs/spec--core-protocol.md); issuer opening-key
rotation follows [sealed key envelopes](docs/spec--sealed-key-envelopes.md).
Client-bound key lifetime and replacement follow
[response binding](docs/spec--response-binding.md). Deployments handle product
provisioning, authenticated administration,
recovery and retention. Those responsibilities do not imply missing DCA
management messages.

Ports and integrations do not change protocol requirements or establish
interoperability by themselves. The
[specification overview](docs/spec---overview.md#proposals) records individual
proposal statuses, and the [evidence index](verification/claim-index/README.md)
records what has actually been demonstrated.

## Direction

- Keep [profile composition](docs/spec--profiles.md#11-composition-rules) explicit:
  include every selected profile's dependencies and verify the duties for that
  combination.
- Maintain [reference slices](js/README.md#publisher-client-and-issuer-artifacts)
  that implementers can copy without adopting a framework.
- Use [vectors, fixtures, contracts and conformance lanes](verification/README.md#choose-evidence-by-the-boundary-under-test)
  for evidence at the boundary being tested; bounded results do not imply
  complete profile or deployment compatibility.
- Prefer a small worked example that exposes intermediate values and lets an
  implementer replace one stage at a time.
