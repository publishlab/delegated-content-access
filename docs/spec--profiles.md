# DCA v1 conformance profiles

Status: Public Working Draft

## Abstract

This document defines the minimum interoperable DCA v1 profile and optional
profiles that compose the HTML carrier, browser-origin enforcement,
period-key caching, content compression, client-bound key custody and
recipient-grant unlock. It distinguishes what an implementation supports
from what a deployment enables and selects.

<a id="1-scope-and-requirements-language"></a>
## 1. Introduction

This document selects mechanisms defined by the DCA topic specifications. It
does not reproduce their algorithms, wire grammar, authority or local failure
rules. A profile adds requirements that only the complete composition creates;
the linked topic specification remains the normative specification for each mechanism.
The [overview glossary](spec---overview.md#terms-across-the-specifications)
distinguishes a profile from an endpoint binding, response agreement and key kind.

The profile names in this document identify conformance claims. They are not
wire values unless another specification explicitly carries them.
While this specification is an unreleased draft, its provisional identifiers
may evolve with an explicitly identified draft revision; a draft conformance
claim must identify that revision. The following identity rule governs released
profiles.
Each identifier names the fixed duties and dependency contract this document
assigns to it. Editorial clarification and use of an explicitly specified
compatible extension point do not change that identity. A later DCA release
may reuse an unchanged profile identifier; it MUST use a distinct identifier
when it changes duties, dependencies or their interpretation incompatibly.
This rule also applies to the baseline: `dca-profile-baseline` denotes the DCA
v1 baseline duties below, not a moving alias for the latest release.

This document designates `dca-profile-baseline` as the **baseline**: the one
default profile from which DCA v1 implementations start. The term and the
identifier refer to the same profile; baseline is not a second unnamed profile
or a layer above it. The baseline is the interoperability floor, not a
deployment recommendation:
[deployment guidance](guide--deployment-patterns.md#choosing-profiles)
describes which optional profiles a deployment adds and who decides.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

### 1.1. Separate profile documents

This document is the profile catalogue and defines shared selection and
composition rules. Each specialized feature keeps its profile duties with its
feature specification in `spec-profile--<name>.md`. This catalogue records
which complete composition an implementer selects, its dependencies and where
to read its duties. Each feature document states its status and whether the
profile is required or optional; the filename alone implies neither.

The [content groups profile](spec-profile--content-groups.md) is
currently a **Proposal** for an optional profile. Its separate document keeps
window seeds, content connectors and their cross-role requirements together.
It does not change the current baseline or adopted profile requirements.

The optional [compact ECDH profile](spec-profile--compact-ecdh.md),
`dca-profile-compact-ecdh`, depends on `dca-profile-baseline`. It adds publisher
HPKE sealing and compressed-point transport, client selector relay, and issuer
configuration-gated opening. A publisher selects it per issuer block using
`envelope`; the issuer public key and keyId can remain the same. Its separate
specification defines the complete construction and duties. Baseline ECDH stays
unchanged; support does not require use for every issuer.

## 2. Mechanism selection states

For a mechanism or profile in this document:

- **implements** means the role contains conforming behavior and can be
  configured to use it;
- **enables** means deployment configuration permits its use;
- **authors** means a publisher makes an item-opening or marked alternative available
  in a protected delivery;
- **emits** means a producer places an operation's protocol member or result on
  the wire;
- **offers** means one peer advertises a selectable behavior;
- **selects** means the profile's deciding actor or trusted configuration
  chooses behavior for its declared scope, such as an issuer endpoint, render, item,
  request or response; and
- **accepts** means the receiving peer admits and applies the selected result.

Implementation does not imply enablement or selection. A mandatory-to-
implement mechanism MAY remain disabled when the deployment selects another
complete compatible path. Enabling one role's mechanism does not imply that
another role supports it.

A delivery MAY carry optional material as one authored alternative; its
presence does not require a recipient to select or use it for every operation.

An implementation MUST NOT infer from field presence alone that omission of
another form selects the remaining form. The owning profile defines whether an
omission removes a fallback and which duties complete the retained alternative.
Before relying on that alternative, configuration MUST establish every assigned
relay, admission, consumption or conversion duty through the role that
recovers a usable dependency form or consumes the optional form. Relay does not
imply interpretation.

A deployment configuration MAY request only its most-specific profile names.
Before using that configuration, an implementation MUST resolve the baseline
and every transitive profile dependency and validate the selected duties,
algorithms and transport. A product MAY package that configuration as a profile
set or deployment preset; such a package is not a new DCA profile and MUST NOT
weaken the requirements of the profiles it selects. Conformance reporting names
both the requested profiles and the resolved profile closure.

### 2.1. Practical selection scopes

The named profiles do not all present the same kind of implementer choice:

- `dca-profile-baseline` is the baseline resolved for every DCA v1 claim, not an
  optional feature toggle.
- `dca-profile-html-carrier` is selected per delivery by the publisher's
  publication arrangement, for clients that implement the profile.
- `dca-profile-browser-origin` is selected by a trusted browser-endpoint contract
  for routes that rely on calling-page-origin admission. An observed `Origin`
  header does not select it.
- `dca-profile-period-keys` and the chain-key profile govern publisher-authored
  optional item-opening alternatives; their role duties apply only where the
  deployment relies on those alternatives.
- `dca-profile-content-compression` is selected per item by the publisher
  (Section 6).
- a client-bound custody profile combines an endpoint contract, a client offer,
  issuer selection and response confirmation for one method.
- `dca-profile-recipient-grant-unlock` is selected for one recipient attempt by
  trusted host configuration of the accepting issuer, publisher and resource;
  the bearer or an untrusted link does not make that selection.

The baseline does not select another named profile. It directly composes the
required mechanisms listed in Section 3. Optional profiles resolve the baseline
as their dependency; a focused mechanism selected by the baseline does not
thereby become a nested profile.

A conformance report may present the requested profiles and their resolved
closure as arrays; the
[profile catalogue README](../verification/profile-catalogue/README.md)
defines that projection.

## 3. `dca-profile-baseline` profile

The baseline profile is one complete path. The publisher delivers the
protected items in one serialized JSON document, and the issuer returns an
item's content key in direct transport mode over HTTPS. A conforming
baseline implementation supports the portions applicable to each role it
claims.

### 3.1. Common substrate

All roles in the path implement the applicable requirements of:

- [spec--core-protocol.md](spec--core-protocol.md);
- [spec--data-format.md](spec--data-format.md);
- [spec--content-protection.md](spec--content-protection.md);
- [spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md);
- [spec--response-binding.md](spec--response-binding.md); and
- the DCA HTTPS JSON mechanism in
  [spec--http-binding.md](spec--http-binding.md).

The common cryptographic substrate is canonical unpadded base64url, ES256 for
the publisher assertion and AES-128-GCM for item protection. Each claimed role
MUST implement the operations it performs.

### 3.2. Publisher requirements

A baseline publisher:

- produces at least one protected item and a conforming ES256
  `resourceJWT`, signed before item encryption;
- encrypts each item under the content AAD of
  [content protection Section 3.2](spec--content-protection.md#32-content-aad)
  using the fixed twelve-zero-octet nonce and a fresh independent key for one
  encryption, and omits item `aad` and `nonce` members;
- implements the JSON delivery of
  [data format Section 6](spec--data-format.md#6-object-delivery);
- authors at least one usable issuer-mediated item content-key envelope for
  every item;
- declares `contentEncodings` as
  [content protection Section 8.1](spec--content-protection.md#81-ordered-representation-layers)
  requires;
- implements the `ecdh-p256` publisher-to-issuer envelope; and
- emits each issuer envelope using the algorithm selected for that issuer.

The publisher MAY also implement the HTML carrier (Section 9) and optional
item-opening alternatives.

### 3.3. Issuer requirements

A baseline issuer:

- implements ES256 publisher verification and the core processing order;
- implements the `ecdh-p256` envelope opener and item content-key result;
- implements direct response representation; and
- exposes a conforming DCA HTTPS JSON endpoint.

Caller authentication and business policy remain deployment choices inside
[core Section 6.2](spec--core-protocol.md#62-authentication-and-policy).

### 3.4. Client requirements

A baseline client:

- consumes the JSON delivery as serialized octets under
  [data format Sections 2, 6 and 7](spec--data-format.md#6-object-delivery);
  a client that accepts only a language-native object does not meet this
  duty;
- implements the core request relay;
- implements DCA HTTPS JSON with direct response admission;
- admits a response coordinate only when it was presented by the associated
  request or belongs to a deterministically checkable admissible result set
  that an implemented, selected capability extension derives from an admitted,
  presented source coordinate, under [core Section 7](spec--core-protocol.md#7-baseline-issuer-core-result);
- processes `contentEncodings` as
  [content protection Section 8.1](spec--content-protection.md#81-ordered-representation-layers)
  requires; and
- builds the content AAD of
  [content protection Section 3.2](spec--content-protection.md#32-content-aad)
  from the captured render ID and item name, uses the implicit twelve-zero-octet
  nonce, ignores carried item `aad` and `nonce` members, and
  opens the protected item under the admitted 16-octet `contentKey`.

It need not implement the HTML carrier, any named content transform,
reusable period capabilities, chain keys, client-bound custody or browser
CORS. A baseline client that parses no HTML and supports no transform
conforms.

### 3.5. Mandatory-to-implement versus selected algorithms

`rsa-oaep` is optional to implement. A deployment MAY select `rsa-oaep` for an
issuer when both publisher and issuer implement it.

Direct response representation is mandatory to implement for baseline issuer
and client roles but optional to enable for deployments that select a complete
client-bound profile. A client-bound-only deployment is conforming only when
its endpoint fails rather than silently selecting direct representation.

### 3.6. Compatibility with a baseline-only client

A baseline-only client needs all of the conditions below to consume a
delivery. This section summarizes the cited requirements and adds none.

- **Key route.** Every item has an envelope from which the issuer of a usable
  issuer block returns that item's content key
  ([core Section 9](spec--core-protocol.md#9-delegation-completeness)).
- **Endpoint configuration.** The client holds trusted endpoint configuration
  for that issuer in the publisher's context
  ([core Section 9](spec--core-protocol.md#9-delegation-completeness)); the
  delivery supplies no endpoint.
- **Carrier.** The publication offers the delivery as the JSON document,
  through the access arrangement the deployment has established for its
  publications, and that document supplies the ciphertext of each item the
  client is to open. An HTML-only publication does not meet this condition,
  and neither does a conversion that the client cannot use (Section 9 and
  [HTML carrier Section 2](spec-profile--html-carrier.md#2-profile-selection-and-role-duties)).
- **Representation.** No item carries `contentEncodings`. The baseline
  guarantees no named decoder, so a baseline client fails a marked item
  unless it supports every named transform (Section 3.4).
- **Endpoint.** The issuer route's endpoint admits the client's request under
  DCA HTTPS JSON, with the caller authentication that the deployment chose
  (Section 3.3). An endpoint that admits browser-origin callers only refuses
  a request without `Origin`
  ([browser-origin Section 2.2](spec-profile--browser-origin.md#22-observed-origin-admission)).
- **Response.** The endpoint returns the direct response representation. A
  client-bound-only endpoint fails the request instead (Section 3.5).

Obtaining a content key satisfies one condition. The client still needs
support for each item's content representation; obtaining the key or
completing the HTTPS exchange establishes no such support.

## 4. `dca-profile-browser-origin` profile

This optional profile composes the baseline with the DCA browser-origin mechanism
in [the browser-origin profile](spec-profile--browser-origin.md). The
publisher, browser client, issuer endpoint and any trusted proxy implement the
requirements assigned to them there.

[Security model Section 4](spec--security-model.md#enforcement-boundary) and
[browser-origin security considerations](spec-profile--browser-origin.md#3-security-considerations-browser-failures-and-privacy)
state what this boundary does not cover.

Credentialed browser mode
([browser-origin Sections 2.4 and 2.5](spec-profile--browser-origin.md#24-cors-response))
is not a separately named DCA profile.

## 5. `dca-profile-period-keys` profile

The optional [period-key profile](spec-profile--period-keys.md#2-profile-selection-and-role-duties)
selects reusable period-key supply, item wraps, issuer delivery and client
caching. It depends on `dca-profile-baseline`; every affected role follows
the duties in that document. Selection is required when a publication relies
on period-key wraps alone for opening.

### 5.1. `dca-profile-chain-keys` profile

The optional [chain-key profile](spec-profile--chain-keys.md#12-profile-selection-and-dependencies)
depends on `dca-profile-period-keys`. It adds the canonical construction,
chain supply, relay and response duties defined together in that document.
Supply forms and issuer output choices do not create further profile names.

<a id="52-fixed-v1-width-and-security-positioning"></a>
### 5.2. Fixed v1 width

Every delivered `contentKey`, `periodKey` and positioned `chainKey` is 16
octets, as [envelopes Section 2](spec--sealed-key-envelopes.md#2-envelope-model)
requires.

## 6. `dca-profile-content-compression` profile

This optional profile composes the baseline with the `gzip` transform in
[content protection Section 8.2](spec--content-protection.md#82-gzip-transform).
The baseline already requires ordered `contentEncodings` processing; this
profile adds one guaranteed transform sequence. It changes only the publisher
and client roles. Issuers and their key-delivery behavior are unaffected and
acquire no duty.

A publisher that claims the profile implements the `gzip` forward operation
and can emit an item whose `contentEncodings` is exactly `["gzip"]`. A client
that claims the profile implements the `gzip` inverse operation and opens
such an item. Each role MUST meet the stream contract of that section in
full; a decoder that accepts concatenated members, ignores trailer integrity
or releases partial output does not satisfy the claim.

Support is mandatory for a role that claims the profile. Use stays a per-item
publisher choice: the publisher MAY compress an item or leave it unencoded,
and it selects compression only where the deployment has established that the
intended clients support the profile. The list that an item carries is the
selection signal. The profile defines no capability negotiation, unlock-time
offer or HTTP compression behavior.

The profile guarantees the single-layer sequence `["gzip"]`. It does not
prohibit another sequence that publisher and client separately support, and
it guarantees neither a repeated `gzip` layer nor `gzip` combined with
another transform. A later optional transform does not weaken this guarantee.

A delivery claiming compatibility with a baseline-only client MUST omit
`contentEncodings`.

## 7. Client-bound custody profiles

The optional profiles `dca-profile-client-bound-ecdh-p256` and
`dca-profile-client-bound-rsa-oaep` select the corresponding methods in
[spec--response-binding.md](spec--response-binding.md). They layer on the HTTPS
channel and do not replace issuer authentication.

For either profile:

- the client implements and enables one method, retains its non-extractable
  private key and offers the matching public JWK;
- the issuer endpoint implements that method, admits the offer before opening
  publisher-supplied keys when client-bound delivery is required, and confirms
  selection in the response;
- every delivered content, period or selected chain key uses the selected
  wrapped key-entry form; and
- the client admits the transport and opens each accepted key as
  [response binding Section 6](spec--response-binding.md#6-client-bound-common-representation)
  requires.

Required client-bound delivery and any direct fallback follow the endpoint
response agreement of
[response binding Section 4](spec--response-binding.md#4-selection-and-agreement).

The ECDH-P256 and RSA-OAEP methods are independent alternatives. Implementing
one does not imply the other. Either method may protect a selected chain-key
result; that composition adds no profile identifier or chain-key construction.

The client-bound `ECDH-P256` method (HKDF-SHA-256) is distinct from the
`ecdh-p256` envelope
([envelopes Section 4](spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope),
no KDF).

## 8. `dca-profile-recipient-grant-unlock` profile

The optional [recipient-grant unlock profile](spec-profile--recipient-grant-unlock.md#11-profile-selection-and-dependencies)
depends on `dca-profile-baseline`. It selects a bearer-credential issuer
unlock path for one accountless recipient. The feature document defines its
grant, endpoint, role and conformance duties. Browser and HTML use additionally
select their respective profiles.

## 9. `dca-profile-html-carrier` profile

The optional [HTML carrier profile](spec-profile--html-carrier.md) depends on
`dca-profile-baseline` and selects HTML extraction for publisher and client.
Its feature document defines carrier selection and compatibility duties.
Issuer unlock behavior is unchanged.

<a id="10-dca-profile-html-content-map-profile"></a>
## 10. Candidate HTML content-map profile

The [protected-HTML content-map proposal](spec-proposal--html-content-map.md)
explores an optional reconstruction profile. It is not selected by this
catalogue, and `dca-profile-html-content-map` is not yet a DCA v1 conformance
claim. The prototype and its tests evaluate the proposal only.

<a id="11-composition-rules"></a>
## 11. Composition rules

Profiles compose only when every affected role implements and selects their
combined requirements. The rows below list the combinations that a rule
requires or forbids. A response-representation layer such as a client-bound
method composes independently except where a row states an exclusion.

| Combination | Status |
| --- | --- |
| recipient grant + browser origin | Required for a browser grant caller; explicit Authorization and exact-Origin admission both apply |
| recipient grant + period or chain capability in one selected attempt | Forbidden; the client omits the members that [recipient-grant Section 3](spec-profile--recipient-grant-unlock.md#3-presentation) lists, even when empty; the issuer refuses a request that carries any of them, and the client refuses a period or chain result (recipient-grant Sections 4 and 5) |
| both client-bound methods in one response | Forbidden; one offered and selected method applies to the response |
| direct-mode and client-bound key entries in one response | Forbidden |
| unknown marked wrap or transform + base interpretation | Forbidden fallback |

The table is not a pairwise allowlist for the named profiles above. An
unlisted combination of named profiles may compose when every affected role
implements and selects the combined duties and no applicable rule excludes the
combination. This does not waive interaction evidence for a conformance claim.

Compact ECDH composes with the other named profiles under its own selector rules:

- Recipient grant + compact ECDH composes. The recipient-grant issuer opens a compact-selected item envelope when
  trusted configuration lists both the ordinary procedure and `compact-ecdh` for that keypair
  ([compact ECDH Section 2](spec-profile--compact-ecdh.md#2-roles-and-selection)). The result still holds item
  content keys only.
- A compact-selected issuer block carries an extension-defined sealed field only when the owning mechanism defines
  the payload width and binding that
  [compact ECDH Section 3.1](spec-profile--compact-ecdh.md#31-publisher-delivery) requires. Another issuer block
  in the same delivery may use the ordinary procedure.

Proposal guidance for content groups follows. The
[content groups profile](spec-profile--content-groups.md) is a Proposal, so these lines describe its draft and the
reference code; they add no composition rule to this catalogue and no conformance claim.

- Recipient grant + content groups does not compose. A content-groups request carries `periodGeometry`, one of
  the members recipient-grant Section 3 forbids, so the table's period-or-chain row applies: the recipient-grant
  issuer refuses the request. The recipient client refuses the period-key, chain-key and geometry
  sections named in recipient-grant Section 5, including empty sections. An unselected proposal
  member such as `contentGroupKeys` is ignored and grants no usable capability; it does not select
  content-group processing. Any future composition must define its result admission. The reference recipient-grant issuer
  also refuses the content-groups issuer contribution when it is built.
- Content-group seeds use the ordinary `ecdh-p256` envelope, and the proposal defines no compact width or binding
  for a seed. The reference publisher refuses seeds in a compact-selected issuer block. An ordinary issuer block
  may carry seeds in a delivery whose other issuer block selects compact ECDH.

A new profile not named in this specification is not automatically forbidden.
An implementation MUST NOT claim interoperability for it until the profile
defines:

- its identifier, baseline relationship and dependency closure;
- every affected role and its implementation-support duties;
- the trusted facts that enable it;
- its authored alternatives, emitted results and offers, as applicable;
- the scope, timing, deciding actor or trusted fact, and signal for each
  selection;
- the representation used at every changed role boundary;
- acceptance, unsupported and refusal behavior;
- whether omission removes a fallback or leaves another complete item-opening alternative;
- interactions and exclusions with other profiles; and
- the scope reported by its conformance claim.

### 11.1. Profile validity

A profile has exactly one identifier. This document defines no alias: a
resolver MUST reject an identifier it does not know and MUST NOT map another
spelling to a known profile.

An optional profile MUST do at least one of the following:

- assign at least one substantive requirement of its own to a role; or
- compose at least two effective direct dependencies.

A direct dependency is effective unless it repeats another direct dependency
or another direct dependency already requires it. A narrower permitted
algorithm, transport or acceptance condition is a substantive requirement. A
restatement of a dependency's requirement is not, and neither is a
placeholder duty. A profile with no requirement of its own and one effective
dependency is a second name for that dependency and is invalid. Two
dependencies that state the same requirements do not make a composition,
even when neither requires the other.

Profile dependencies MUST form an acyclic graph in which every optional
profile requires the baseline. A profile MUST NOT depend on itself. A
dependency that several requested profiles share resolves once. The
requirements of a profile and its dependencies MUST be satisfiable together.

The baseline is exempt from the composition test: it is the root that every
other profile requires.

A catalogue check can establish the graph conditions: known identifiers, no
cycle, no repeated edge, and at least one assigned duty or two effective
direct dependencies. Whether a requirement is substantive, whether two
dependencies differ in substance and whether their requirements hold
together are editorial judgments made when the profile is defined.

A rule that must hold whenever two profiles are both selected belongs to one
of those profiles, so that a deployment listing both by hand cannot bypass
it.

### 11.2. Candidate browser-integration profile

The [browser-integration proposal](spec-proposal--browser-integration.md) explores
`dca-profile-browser-integration`, a client-side decoded-content handoff with
optional coordination interfaces. It is not selected by this specification and
is not a current DCA v1 conformance profile. Its prototype and tests evaluate the
proposal only. The candidate depends on baseline, changes no wire field, key
authority or cryptographic construction, and adds no duties to baseline-only
clients, publishers or issuers.

## 12. Conformance claims

A conformance claim names:

- the DCA version;
- each role implemented;
- the envelope algorithms implemented;
- every named content transform implemented, and the profile or external
  specification that defines it;
- every optional profile implemented;
- every profile enabled for the deployment; and
- any external endpoint or credential profile required to complete the path.

The claim also records the requested profile leaves, their resolved dependency
closure and the selection scope for any duties that change which cross-role
path ran. For the chain-key profile this includes publisher-to-issuer supply
mode and issuer-to-client response form; naming the profile alone does not claim
that every permitted form ran.
For recipient-grant unlock the claim carries the evidence of
[recipient-grant Section 6](spec-profile--recipient-grant-unlock.md#6-conformance-boundary).

A role's conformance claim requires its applicable baseline duties and the
duties and dependencies of every optional profile it claims. Selecting an
optional profile does not invalidate baseline conformance or remove those
duties. Consuming a publication using that profile requires a client
implementing its applicable consumer duties, in addition to the other
requirements of the publication. Two implementations can satisfy their
respective conformance claims without interoperating on a publication
requiring a profile one does not implement.

[Deployment guidance](guide--deployment-patterns.md#describing-support-and-compatibility)
explains how to distinguish these claims when describing an implementation
or a service. This distinction defines no capability-advertisement or
negotiation mechanism.

An implementation MUST NOT claim an optional profile merely because it ignores
the profile's fields or relays them opaquely. A relay may claim only its relay
duty when the profile assigns it no interpretation work. A chain-key profile
relay client accepting projected period keys also claims their
request-associated admission duty, without claiming chain derivation.

Passing one vector or using the reference source is not complete conformance.
Each claim requires the positive, negative, ordering and composition evidence
identified by its normative specifications.

The informative [verification overview](../verification/README.md#from-a-profile-name-to-evidence)
shows where the current primitive, vector, fixture, implementation and
composition evidence lives, which commands execute it and which named-profile
claim aggregation is not yet implemented.

## 13. Security considerations

A selected profile retains the security and failure boundaries of each
mechanism it composes. The [mandatory security model](spec--security-model.md)
defines the attacker and trust boundaries used to evaluate every profile.

## 14. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [DCA core protocol](spec--core-protocol.md)
- [DCA data format](spec--data-format.md)
- [DCA content protection](spec--content-protection.md)
- [DCA publisher-to-issuer sealed-key envelopes](spec--sealed-key-envelopes.md)
- [DCA issuer-response binding](spec--response-binding.md)
- [DCA HTTP binding](spec--http-binding.md)
- [DCA browser-origin profile](spec-profile--browser-origin.md)
- [DCA HTML carrier profile](spec-profile--html-carrier.md)
- [DCA recipient-grant unlock profile](spec-profile--recipient-grant-unlock.md)
- [DCA period-key profile](spec-profile--period-keys.md)
- [DCA chain-key profile](spec-profile--chain-keys.md)
- [DCA security model](spec--security-model.md)

## 15. Informative References

- [DCA deployment patterns](guide--deployment-patterns.md)
- [DCA profile catalogue](../verification/profile-catalogue/README.md)
