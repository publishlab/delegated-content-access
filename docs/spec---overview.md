# DCA specification overview

Status: Public Working Draft

## Purpose

This is the entry point for DCA specification documents. It identifies which
document owns each normative subject and keeps readable design explanation
separate from protocol authority.

## Document status

Every public specification, proposal, guide and design note carries one of
three statuses in its header:

- **Public Working Draft**: normative text that implementers may evaluate. It may
  change incompatibly before DCA v1.
- **Proposal**: a candidate change. It is not part of DCA v1 unless the editors
  adopt it into its target specification.
- **Informative Draft**: explanation, guidance or examples. It defines no protocol
  requirement.

A section that a Public Working Draft labels informative or editorial states no
requirement. Test vectors and reference implementations are informative
evidence; the specification text defines conformance.

Cite the publication commit for an immutable revision;
the documents carry no manually maintained revision dates.

Editors promote a document only after reconciling it with current authority
documents, pinning its cryptographic transcript where applicable, and providing
neutral vectors and a bounded implementation.

## Start here

Implement the baseline first.
[spec--profiles.md](spec--profiles.md#3-dca-profile-baseline-profile) Section 3
names `dca-profile-baseline`, the minimum interoperable path, and lists what
each role owes under it. Read [spec--core-protocol.md](spec--core-protocol.md)
next, then the documents profiles Section 3.1 lists and the security model.
Period keys, chain keys, browser-origin admission, recipient grants, HTML
carriage and browser content handling add reading only when those profiles are
selected. Everything under Proposals is unselected.

For a concrete first exchange, follow the
[minimal key exchange](design--data-format--example.md#minimal-key-exchange--html-delivery)
from delivery through an issuer response to opened plaintext. It selects the
optional HTML carrier and uses illustrative cryptographic placeholders.

The optional [compact ECDH profile](spec-profile--compact-ecdh.md) combines
HPKE with compressed-point envelope transport. Its per-issuer selector chooses
the compact procedure while retaining the same issuer keypair and keyId.

## Terms across the specifications

The binding names refer to related parts of the issuer endpoint contract, not
four independently selected security mechanisms:

- **Request binding** names the selected endpoint rules for admitting an
  unlock request, including checks that use verified claims before policy or
  key opening. The core defines the [processing
  order](spec--core-protocol.md#6-issuer-processing); the endpoint mechanism
  supplies its checks.
- **Delivery binding** is the core's contextual name for the rules that admit
  a signed delivery `origin`. The selected endpoint mechanism defines those
  rules; the HTTPS mechanism defines the [canonical signed
  origin](spec--http-binding.md#32-canonical-signed-origin).
- **Endpoint binding** names the request and response channel mechanism and
  its applicable caller checks. The [endpoint
  specification](spec--http-binding.md#2-endpoint-binding-mechanisms)
  owns its concrete mechanisms.
- **HTTPS endpoint binding** means the [DCA HTTPS JSON
  mechanism](spec--http-binding.md#3-dca-https-json), the baseline
  endpoint binding. Its browser-origin checks apply when that optional profile
  is selected.

**Key kind** is the capability a response key entry carries (`contentKey`,
`periodKey` or `chainKey`), as
[response binding Section 6](spec--response-binding.md#6-client-bound-common-representation)
fixes it. A **profile** is a named composition of role duties and mechanisms
whose [dependencies](spec--profiles.md#1-introduction) are resolved before a
conformance claim.

An **unresolved item** has no locally admitted key that opens it. An
**admissible result set** is defined in
[core Section 6.1](spec--core-protocol.md#61-presented-coordinates). A **key
entry** is defined in
[response binding Section 5](spec--response-binding.md#5-direct-representation).

## Document map

| Document | Intended ownership | Current status |
| --- | --- | --- |
| This overview | Specification boundaries and reading order | Public Working Draft |
| [spec--core-protocol.md](spec--core-protocol.md) | Roles, signed-resource authentication, unlock flow, delegation completeness, response authority, and core failures | Public Working Draft |
| [spec--data-format.md](spec--data-format.md) | Publisher-to-client JSON and markup carriers, structural processing, identifiers, and extension handling | Public Working Draft |
| [spec--content-protection.md](spec--content-protection.md) | Per-item keys, content AEAD, period-key content-key wrapping, item opening, deferred-ciphertext invariants, and transform boundary | Public Working Draft |
| [spec--response-binding.md](spec--response-binding.md) | Issuer-response channel requirements, direct representation of keys, optional client-bound methods, response admission, and downgrade behavior | Public Working Draft |
| [spec--http-binding.md](spec--http-binding.md) | Shared HTTPS JSON endpoint, canonical signed origin, request/response exchange and cache boundary | Public Working Draft |
| [spec-profile--browser-origin.md](spec-profile--browser-origin.md) | Optional browser observed-Origin admission, proxy handling, CORS and preflight duties | Public Working Draft |
| [spec-profile--html-carrier.md](spec-profile--html-carrier.md) | Optional HTML carrier selection and publisher/client extraction duties | Public Working Draft |
| [spec-profile--recipient-grant-unlock.md](spec-profile--recipient-grant-unlock.md) | Optional recipient-grant presentation and admission, common signed JWT, optional issuer-local opaque reference, and item content-key limit | Public Working Draft |
| [spec--profiles.md](spec--profiles.md) | Minimum interoperable baseline, optional-profile composition, mechanism selection states, and conformance claims | Public Working Draft |
| [spec-profile--period-keys.md](spec-profile--period-keys.md) | Optional period-key capabilities, supply, results, caching and role duties | Public Working Draft |
| [spec-profile--chain-keys.md](spec-profile--chain-keys.md) | Optional chain-key construction, window geometry, supply, carrier, delegation, bounds and role duties | Public Working Draft |
| [spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md) | Publisher-to-issuer envelope algorithms and BIND | Public Working Draft |
| [spec-profile--compact-ecdh.md](spec-profile--compact-ecdh.md) | Optional HPKE envelopes, compressed-point transport, per-issuer selection and client relay | Public Working Draft |
| [spec--security-model.md](spec--security-model.md) | The security boundary governing the specification set | Public Working Draft |

Each document owns the subjects its row names. Core owns the processing order
that composes the focused mechanisms. The profile catalogue owns shared
selection and composition rules; each specialized profile document keeps its
feature's mechanism and role duties together. Where two documents disagree on
a subject, the owner of that subject controls and the other document has a
defect to reconcile. A guide or design note never controls a normative subject.

### Proposals

Profile documents use `spec-profile--<name>.md` and keep their status in the
header. The [profile catalogue](spec--profiles.md#11-separate-profile-documents)
explains this organization. The content groups profile is a Proposal and
is not an adopted profile.

Files named `spec-proposal--<change>.md` state a candidate change in the form
its target section uses and carry Proposal status. A Proposal does not override a
Public Working Draft by using requirement words. Partial adoption gives remaining
candidate text no authority and establishes no complete reference conformance
claim.

| Proposal | Target |
| --- | --- |
| [spec-profile--content-groups.md](spec-profile--content-groups.md) | Optional content groups profile: window seeds, connectors and cross-role delivery |
| [spec-proposal--browser-integration.md](spec-proposal--browser-integration.md) | Candidate client-side handoff, output lifetime, registry and context interfaces; profiles |
| [spec-proposal--html-content-map.md](spec-proposal--html-content-map.md) | Profiles, Section 10; protected-HTML reconstruction |
| [spec-proposal--content-description-and-placement.md](spec-proposal--content-description-and-placement.md) | Data format, content protection, browser integration and HTML content-map proposal |

## Readable companions

Readable design documents explain why the protocol has its shape, how the
pieces interact, and how developers configure and debug it.

| Document | Intended audience and purpose |
| --- | --- |
| [guide--period-keys.md](guide--period-keys.md) | Human-readable period-key model and examples, with the optional chain model in its separate companion |
| [guide--integration--period-keys.md](guide--integration--period-keys.md) | Practical period-key integration path through the reference source, wire members, and runnable reuse tests |
| [guide--integration--metering.md](guide--integration--metering.md) | Issuer integration for metered grants, including policy input, commit timing, and observable limits |
| [guide--reference-implementation-status.md](guide--reference-implementation-status.md) | Revision-scoped reference observations and evidence limits, separate from protocol requirements |
| [guide--browser-content-presentation.md](guide--browser-content-presentation.md) | Owner-selected browser rendering, template-authored maps and independent article reconstruction |
| [guide---overview.md](guide---overview.md) | Deeper explanation of how DCA's parts fit together |
| [guide--chain-keys.md](guide--chain-keys.md) | Readable chain-key model: geometry, supply, delegation and client relay |
| [guide--chain-keys--label-mapping.md](guide--chain-keys--label-mapping.md) | Compact UTC labels, calendar validation and optional integer conversion recipe |
| [guide--key-flow--diagrams.md](guide--key-flow--diagrams.md) | Illustrated key flow: publisher sealing, issuer envelope opening and grants, client content opening |
| [guide--deployment-patterns.md](guide--deployment-patterns.md) | Browser, server, edge and hybrid ways to place the DCA client role |
| [guide--unlock-fallback.md](guide--unlock-fallback.md) | Deployment-owned client route walk, fallback issuers, health and emergency operation; each independent exchange remains governed by core and its selected transport profile |
| [guide--browser-integration.md](guide--browser-integration.md) | Evaluating the browser-integration proposal: examples, rationale and limitations |
| [design--data-format--example.md](design--data-format--example.md) | Worked HTML exchanges with illustrative values |
