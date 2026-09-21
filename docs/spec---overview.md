# DCA specification overview

Status: Public Working Draft

## Purpose

This is the entry point for DCA specification documents. It identifies which
document owns each normative subject and keeps readable design explanation
separate from protocol authority.

The authors are still assembling the specification set. A Proposal does not
override a Public Working Draft merely because it uses requirement words.

## Document status

Every public specification, proposal, guide and design note carries one of
three statuses in its header:

- **Public Working Draft**: normative text that implementers may evaluate. It may
  change incompatibly before DCA v1.
- **Proposal**: a candidate change. It is not part of DCA v1 unless the editors
  adopt it into its target specification.
- **Informative Draft**: explanation, guidance or examples. It defines no protocol
  requirement.

Draft snapshot: 2026-09-21. Cite the publication commit for an immutable revision;
the documents carry no manually maintained revision dates.

## Start here

Implement the baseline first.
[spec--profiles.md](spec--profiles.md#3-dca-v1-direct-https-baseline) Section 3
names `dca-v1-direct-https`, the minimum interoperable path, and lists what
each role owes under it. Read
[spec--core-protocol.md](spec--core-protocol.md) next for the unlock flow, then
the documents the profile requirements cite. Everything under Proposals is
unselected.

Optional profile names resolve through their dependencies. A deployment may
bundle selected profile leaves and duties into an opinionated preset, but the
preset is configuration rather than another protocol profile. The profile
specification owns the resolved cross-role obligations.

## Document map

| Document | Intended ownership | Current status |
| --- | --- | --- |
| This overview | Specification boundaries, conformance model, and reading order | Public Working Draft |
| [spec--core-protocol.md](spec--core-protocol.md) | Roles, signed-resource authentication, unlock flow, delegation completeness, response authority, and core failures | Public Working Draft |
| [spec--data-format.md](spec--data-format.md) | Publisher-to-client JSON and markup carriers, structural processing, identifiers, and extension handling | Public Working Draft |
| [spec--content-protection.md](spec--content-protection.md) | Per-item keys, content AEAD, exact-period content-key wrapping, item opening, deferred-ciphertext invariants, and transform boundary | Public Working Draft |
| [spec--response-binding.md](spec--response-binding.md) | Issuer-response channel requirements, direct key representation, optional client-bound methods, response admission, and downgrade behavior | Public Working Draft |
| [spec--browser-http-binding.md](spec--browser-http-binding.md) | Baseline HTTPS JSON endpoint binding and optional browser Origin/CORS mechanism | Public Working Draft |
| [spec--profiles.md](spec--profiles.md) | Minimum interoperable baseline, optional-profile composition, mechanism selection states, and conformance claims | Public Working Draft |
| [spec--period-keys.md](spec--period-keys.md) | Base exact-period capabilities, exact supply, results, caching and role duties | Public Working Draft |
| [spec--period-key-chains.md](spec--period-key-chains.md) | Period-chain canonical construction, window geometry, chain supply, carrier, delegation, bounds and role duties | Public Working Draft |
| [spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md) | Publisher-to-issuer envelope algorithms and BIND | Public Working Draft |
| [spec--security-model.md](spec--security-model.md) | The security boundary governing the specification set | Public Working Draft |

The working core DCA specification owns actor roles, common message flow,
authentication requirements, conformance terminology, and the interfaces
between focused specifications. Focused documents own their complete
mechanism, and the core owns the ordering and composition required for
their guarantees.
The profile specification selects complete combinations and adds requirements
that arise only from composition; it does not take ownership of the selected
mechanisms.

The working `spec--data-format.md` owns the surrounding wire fields; a
disagreement about carrier, placement, or structural admission is a
reconciliation defect rather than competing protocol authority. The focused
sealed-key envelope specification likewise owns envelope algorithms and BIND.

### Proposals

Files named `spec-proposal--<change>.md` state a candidate change in the
form its target section uses. They carry no authority. The editors adopt a
proposal only after the reference implementation and a conformance primitive
prove it; they move its text into the target and remove a declined proposal.
Status
"considered" means a stated intent; "proposed, pending proof" means the spec
text is written and waits for the proofs.

| Proposal | Target | Status |
| --- | --- | --- |
| [spec-proposal--compact-ecdh-envelope.md](spec-proposal--compact-ecdh-envelope.md) | Sealed-key envelopes, Section 4; profiles | Proposed; the envelope construction is not selected and its transcript is not final |
| [spec-proposal--derived-content-aad.md](spec-proposal--derived-content-aad.md) | Content protection, Section 3.2; data format | Proposed, pending proof |
| [spec-proposal--content-transforms.md](spec-proposal--content-transforms.md) | Content protection, Section 8; data format | Proposed, pending proof |
| [spec-proposal--detached-key-supply.md](spec-proposal--detached-key-supply.md) | Core, response binding, browser HTTP binding | Proposed, pending proof |
| [spec-proposal--detached-content.md](spec-proposal--detached-content.md) | Content protection, Section 7; data format | Proposed, pending proof |
| [spec-proposal--client-bound--host-custody-profile.md](spec-proposal--client-bound--host-custody-profile.md) | Profiles, Section 7; response binding | Proposed, pending proof |
| [spec-proposal--period-chain-integer-label-mapping.md](spec-proposal--period-chain-integer-label-mapping.md) | Period-key chains, Section 7.3 | Proposed; restates the existing mapping as integer arithmetic, no wire change |
| [spec-proposal--remove-wire-unlock-url.md](spec-proposal--remove-wire-unlock-url.md) | Data format, core delegation completeness, HTTPS endpoint selection | Proposed; adoption is decided before v1 |

## Capability and dependency index

This index exposes requirements that cross topic boundaries. It is not a
second normative owner; each row links to the specifications that define the
behavior. Reviewers check each applicable capability stage from implemented
and enabled through emitted, offered, selected and accepted.

| Capability | Selection point and affected roles | Conditional prerequisites and fallback | Normative owners |
| --- | --- | --- | --- |
| Direct content-key route | Publisher authors route; issuer authorizes result; client accepts it | Requires the HTTPS endpoint binding plus direct response representation; an authored exact-period route may remain an alternative | [Profiles](spec--profiles.md), [Core](spec--core-protocol.md), [Response binding](spec--response-binding.md), [HTTPS/browser binding](spec--browser-http-binding.md), [Content protection](spec--content-protection.md) |
| Browser Origin/CORS | Browser caller and issuer endpoint select the calling-page-origin boundary | Requires canonical signed and observed origins, exact equality, trusted proxy handling and conditional CORS; non-browser HTTPS does not claim this property | [Profiles](spec--profiles.md), [HTTPS/browser binding](spec--browser-http-binding.md), [Core](spec--core-protocol.md) |
| Exact-period cached route | Publisher emits wraps; client has or obtains exact capability | Wrap and exact capability must describe the same coordinate; candidate miss continues; a conforming issuer-mediated route remains required | [Profiles](spec--profiles.md), [Content protection](spec--content-protection.md), [Period keys](spec--period-keys.md), [Core](spec--core-protocol.md) |
| Content representation transforms | Publisher selects an ordered transform list; client reverses it only after authenticated decryption | Every named transform and its finite processing limits must be supported by the selected profile; unsupported or malformed transforms fail the item | [Content protection](spec--content-protection.md), [Data format](spec--data-format.md), [Profiles](spec--profiles.md) |
| Chain-derived candidate | Selected period-chain profile supplies exact leaves | Every affected role must support the profile duties assigned to it; an exact leaf retains the base content-wrap meaning | [Period-key chains](spec--period-key-chains.md), [Period keys](spec--period-keys.md), [Content protection](spec--content-protection.md) |
| Client-bound key result | Client offers and issuer selects the response representation | Requires compatible client and issuer behavior plus the HTTPS endpoint binding; absence of agreement uses a mutually selected fallback or fails without releasing a key | [Profiles](spec--profiles.md), [Response binding](spec--response-binding.md), [HTTPS/browser binding](spec--browser-http-binding.md), [Core](spec--core-protocol.md) |
| Not-delivered access-group family | Deployment selects the not-delivered-result profile before it interprets a response; the issuer emits the report and the client accepts it | The member delivers no key, and a named family has no delivered period capability under Core Section 7.2; an independently authorized direct content-name result may coexist, while a client that has not selected the profile reads no non-delivery outcome from the member | [Profiles](spec--profiles.md#8-dca-v1-not-delivered-result-profile), [Core](spec--core-protocol.md#72-not-delivered-access-group-families), [Response binding](spec--response-binding.md#3-inputs-and-common-response-form) |
| Candidate deferred-ciphertext delivery | If adopted, publisher omits inline ciphertext under an explicitly selected delivery profile | Delivery profile must obtain the original ciphertext tuple; local opening remains identical to inline opening | No DCA transport owner selected; base invariants only in [Content protection](spec--content-protection.md) and [Data format](spec--data-format.md) |
| Candidate alternative wrap or content transform | If adopted, a named profile is selected by every actor whose behavior changes | Exact transcript, marker, limits and unsupported behavior are profile requirements; unknown optimized forms never fall back to base interpretation | No alternative-wrap profile is selected; the reserved `bind` marker and its no-fallback rule are live in [Content protection](spec--content-protection.md) Section 4 and named in [Data format](spec--data-format.md) Section 3 |

The index remains a compact navigation aid. Stable combination requirements
belong to the profile specification; this table does not restate their full
role obligations.

## Readable companions

Readable design documents explain why the protocol has its shape, how the
pieces interact, and how developers configure and debug it. They should link to
the normative specification instead of duplicating exact grammar or
cryptographic transcripts.

| Document | Intended audience and purpose |
| --- | --- |
| [guide--period-keys.md](guide--period-keys.md) | Human-readable exact period-key model and examples, with the optional chain model in its separate companion |
| [guide--integration--exact-period.md](guide--integration--exact-period.md) | Practical exact-period integration path through the reference source, wire members, and runnable reuse tests |
| [guide--integration--metering.md](guide--integration--metering.md) | Issuer integration for metered grants, including policy input, commit timing, and observable limits |
| [guide--browser-content-presentation.md](guide--browser-content-presentation.md) | Early WIP sketch of a possible publisher callback for opened browser content; no interface is proposed or selected |
| [guide---overview.md](guide---overview.md) | Deeper explanation of how DCA's parts fit together |
| [guide--period-key-chains.md](guide--period-key-chains.md) | Readable period-chain model: geometry, supply, delegation and client relay |
| [guide--deployment-patterns.md](guide--deployment-patterns.md) | Browser, server, edge and hybrid ways to place the DCA client role |
| [guide--unlock-fallback.md](guide--unlock-fallback.md) | Deployment-owned client route walk, fallback issuers, health and emergency operation; each independent exchange remains governed by core and its selected transport profile |

If a readable design guide and a normative specification disagree, the
normative specification controls and the guide has a documentation defect.
When one document has mixed status,
precedence follows the explicit topic or section scope declared by that
document.

## Review and promotion discipline

Each normative statement in this set identifies:

- the actor to which it applies;
- whether it is required or optional;
- the observable interoperability or safety reason for the requirement;
- how optional capability combinations form a complete path;
- what is authenticated or trusted;
- how unsupported, malformed, and conflicting input fails; and
- which conformance evidence can test the statement.

Open design questions should remain visibly marked as open. Authors must not
hide an unresolved choice behind requirement words or require an internal
source-code arrangement that is unnecessary for interoperable behavior.

Editors promote a document only after reconciling it with current authority
documents, pinning its cryptographic transcript where applicable, and providing
neutral vectors and a bounded implementation.
