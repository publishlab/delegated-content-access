# Public draft-period roadmap

Status: Informative Draft

DCA is a public working draft. This list records current priorities for the
draft period. It does not block the initial draft publication.

The [exact period-key path](docs/spec--period-keys.md#53-periodkeyt) is the
compatibility anchor: the publisher supplies one exact `periodKey[t]`, the
key for one publisher, access group, and period coordinate; the issuer grants
it, and the client retains and reuses it for matching content. The
[worked example](docs/spec--period-keys.md#81-exact-issuer-and-exact-client)
shows the complete path. While the editors reorganize profiles, reference code, tests,
and documentation, preserve what works and close its remaining gaps first.

Current [specifications and document
status](docs/spec---overview.md#document-status) govern. The numbers are local
labels for referring to items on this page; they are not issue links. Gaps are
intentional. Completed or rejected items leave this page.

## Fix shortly

- **Supported publisher and issuer entries** [integration, JavaScript] #59 #60
  - **Now:** The browser client has a supported source-copy manifest and
    composition entry. Publisher and issuer implementers must still assemble
    lower-level modules from the integration guides and reference examples.
  - **Next:** Add small, copyable role entries and manifests with validated
    inputs, explicit security-sensitive host dependencies, and focused
    consumer tests. Deliver publisher and issuer entries separately.
  - **Affects:** JavaScript reference, source boundaries, tests, and the
    [exact-period integration guide](docs/guide--integration--exact-period.md);
    no wire change.

- **Browser and issuer admission** [browser, JavaScript] #51 #52 #53
  - **Now:** The specification settles the admission rules. The reference
    still mishandles pre-verification CORS, redirects, response shape and media
    type, production URLs, and one fallback case.
  - **Next:** Fix the settled cases at their owning boundaries; decide the
    remaining fallback case and align the reference.
  - **Affects:** Browser client, issuer HTTP adapter, tests, and
    [fallback guidance](docs/guide--unlock-fallback.md).

## Decide during the draft

- **Checked profile catalogue** [profiles] #38
  - **Now:** The [profile specification](docs/spec--profiles.md) defines
    dependencies and role duties, but no machine-checked catalogue owns them.
  - **Next:** Resolve requested profiles to one checked set used by
    configuration, tests, and claims.
  - **Affects:** Profiles, reference configuration, and profile tests.

- **Profile configuration boundary** [profiles, wire] #39 #41
  - **Now:** The
    [content-key seal-omission prototype](js/v1/extensions/content-key-seal-omission/README.md)
    needs classification. Publisher-to-issuer profile agreement remains
    out-of-band.
  - **Next:** Classify the prototype. Decide whether out-of-band configuration
    is enough or a readable publisher commitment earns its wire cost.
  - **Affects:** Profiles and reference configuration; wire only if a
    commitment is adopted.

- **Period-chain names and derived bytes** [period chains] #33 #35
  - **Now:** The frozen construction still uses the anomalous
    `dca-period-chain-v1` identifier; the target is `dca-v1-period-chain`, but
    the rename is unscheduled. Because the identifier is part of the KDF
    transcript, the rename changes every derived root, state and leaf. One
    output name also remains open.
  - **Next:** Schedule one coordinated rename before v1, settle the remaining
    name, and regenerate and independently check every frozen vector, fixture,
    expected-value test and cross-runtime artifact that embeds the old derived
    bytes.
  - **Affects:** Specification, reference code, vectors, fixtures, tests,
    conformance evidence, bridges, and deployments that pin the current
    identifier or derived bytes.

- **Open wire proposals** [wire] #42
  - **Now:** The [proposal set](docs/spec---overview.md#proposals) covers eight
    candidate wire changes.
  - **Next:** Adopt, fold in, or drop each proposal.
  - **Affects:** Target specifications, reference code, and evidence named by
    each proposal.

- **Browser binding questions** [browser] #54 #55
  - **Now:** The public binding defines POST. A GET carrier and the cache
    partition input outside a publisher page are unassigned questions.
  - **Next:** Assign or reject each question before describing either path as
    supported.
  - **Affects:** Browser binding, deployment guidance, and client integration.

- **Publisher and client key lifecycle** [security, deployment] #44 #45
  - **Now:** Publisher signing-key rotation and the complete client-bound key
    lifecycle are not specified.
  - **Next:** Define rotation, overlap, retirement, retained state, and both
    sides of the transport-key rule.
  - **Affects:** Specifications, reference integration, and deployment
    guidance.

- **Not-delivered result** [profiles, JavaScript] #30
  - **Now:**
    [`dca-v1-not-delivered-result`](docs/spec--profiles.md#8-dca-v1-not-delivered-result-profile)
    is specified as a profile, has no reference implementation, and is being
    reconsidered as ordinary core behavior.
  - **Next:** Keep it as a profile, fold it into core, or drop it; then align
    the reference and tests with that decision.
  - **Affects:** Core and profile specifications, JavaScript reference, and
    tests.

- **Portable reference seams** [JavaScript, ports] #58
  - **Now:** The crypto provider captures host WebCrypto during module load,
    which blocks clean injection. Some tests also require English error text.
  - **Next:** Define a replaceable provider seam and use stable refusal codes
    where another implementation consumes the result.
  - **Affects:** JavaScript reference, ports, and tests.

- **Evidence gaps** [verification] #61 #63
  - **Now:** Malformed AES-GCM acceptance is undecided. One integer-spelling
    case and one exact-versus-chain supply measurement are missing.
  - **Next:** Decide the behavior first, then add the discriminating cases and
    measurements.
  - **Affects:** Specification, domain tests, conformance, and evidence.

- **Browser opened-content presentation** [browser, integration] #64
  - **Now:** The browser client ends at opened bytes. An
    [early WIP sketch](docs/guide--browser-content-presentation.md) illustrates
    how a publisher-owned callback might place and activate content, but no
    interface, discovery namespace, slot convention, or profile is proposed or
    selected.
  - **Next:** Exercise the handoff in one publisher-controlled product
    integration and one independently composed client. Then decide whether
    explicit injection is sufficient, a shared discovery convention earns
    support, or presentation should remain entirely deployment-specific.
  - **Affects:** Browser integration and guidance. No DCA wire, cryptographic,
    access-policy, or profile change without a separate supported use case and
    decision.

- **Reader guidance** [docs] #46
  - **Now:** Important vocabulary and evidence status are spread across the
    public set.
  - **Next:** Add a short glossary and evidence overview. Add focused guidance
    on onboarding, access modelling, protocol concepts, content types, and
    hardening as each subject is ready.
  - **Affects:** Public documentation only.

## Direction, not an issue list

- [Profile composition](docs/spec--profiles.md#9-composition-rules) that tests
  prove: select profiles, resolve one defined set, and run an end-to-end
  scenario for it.
- [Reference slices](js/v1/README.md#publisher-client-and-issuer-artifacts)
  implementers can copy into their own code instead of adopting a framework.
- [Vectors, fixtures, contracts, and conformance
  lanes](verification/README.md#choose-evidence-by-the-boundary-under-test)
  implementers can run against their own implementation.
- Bindings that let another implementation reuse DCA unit tests for extra
  coverage without rewriting them.
- A small [worked example](docs/design--data-format--example.md) that can grow
  into a playground for printing intermediate values and replacing one stage
  at a time.
