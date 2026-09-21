# DCA v1 conformance profiles

Status: Public Working Draft

## Abstract

This document defines the minimum interoperable DCA v1 profile and optional
profiles that compose browser-origin enforcement, exact-period caching,
layered content representations, client-bound key custody and an issuer report
that a family received no capability. It distinguishes what an implementation supports
from what a deployment enables and selects.

<a id="1-scope-and-requirements-language"></a>
## 1. Introduction

This document selects mechanisms defined by the DCA topic specifications. It
does not reproduce their algorithms, wire grammar, authority or local failure
rules. A profile adds requirements that only the complete composition creates;
the linked topic specification remains the normative specification for each mechanism.

The profile names in this document identify conformance claims. They are not
wire values unless another specification explicitly carries them.

This document designates `dca-v1-direct-https` as the **baseline**: the one
default profile from which DCA v1 implementations start. The term and the
identifier refer to the same profile; baseline is not a second unnamed profile
or a layer above it.

The optional profiles make additional capabilities and wire-cost choices
interoperable without requiring every implementation to carry every mechanism.
A deployment can select only the paths it uses and, where the owning profile
permits it, omit redundant request or response material and the work needed to
process it. That can reduce transferred bytes, bandwidth cost and transfer
latency; it does not guarantee lower end-to-end latency. A simple
implementation can remain baseline-only. Each optional profile therefore has
to earn its additional implementation and testing complexity with a complete,
usable cross-role path.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Mechanism selection states

For a mechanism or profile in this document:

- **implements** means the role contains conforming behavior and can be
  configured to use it;
- **enables** means deployment configuration permits its use;
- **authors** means a publisher makes a route or marked alternative available
  in a protected delivery;
- **emits** means a producer places an operation's protocol member or result on
  the wire;
- **offers** means one peer advertises a selectable behavior;
- **selects** means the profile's deciding actor or trusted configuration
  chooses behavior for its declared scope, such as a route, render, item,
  request or response; and
- **accepts** means the receiving peer admits and applies the selected result.

Implementation does not imply enablement or selection. A mandatory-to-
implement mechanism MAY remain disabled when the deployment selects another
complete compatible path. Enabling one role's mechanism does not imply that
another role supports it.

An implementation MAY implement and test one role's profile duties without a
deployed peer. That is support, not operational selection. A delivery MAY also
carry optional material as one authored alternative. Its presence does not
require a recipient to select or use it for every operation.

An implementation MUST NOT infer from field presence alone that omission of
another form selects the remaining form. The owning profile defines whether an
omission removes a fallback and which duties complete the retained route.
Before relying on that route, configuration MUST establish every assigned
relay, admission, consumption or conversion duty through the role that
recovers a usable dependency form or consumes the optional form. Relay does not
imply interpretation.

Private use of a profile's construction or helper code, with no observable
profile duty selected, remains an implementation choice. Where a role converts
optional material to a dependency form, the selected optional path MAY end at
that conversion and downstream roles need only the dependency profile.
Carrying the optional form farther is another selection and binds the
producer, intermediaries and consumer requirements for that continuation.

A deployment configuration MAY request only its most-specific profile names.
Before using that configuration, an implementation MUST resolve the baseline
and every transitive profile dependency and validate the selected duties,
algorithms and transport. A product MAY package that configuration as a profile
set or deployment preset; such a package is not a new DCA profile and MUST NOT
weaken the requirements of the profiles it selects. Conformance reporting names
both the requested profiles and the resolved profile closure.

### 2.1. Practical selection scopes

The named profiles do not all present the same kind of implementer choice:

- `dca-v1-direct-https` is the baseline resolved for every DCA v1 claim, not an
  optional feature toggle.
- `dca-v1-browser-origin` is selected by a trusted browser-endpoint contract
  for routes that rely on calling-page-origin admission. An observed `Origin`
  header does not select it.
- `dca-v1-exact-period` and the period-chain profile govern publisher-authored
  optional routes; their role duties apply only where the deployment relies on
  those routes.
- `dca-v1-content-representations` is selected per item by an authored transform
  list after publisher/client support has been established.
- a client-bound custody profile combines an endpoint contract, a client offer,
  issuer selection and response confirmation for one method.
- `dca-v1-not-delivered-result` is selected by endpoint/deployment
  configuration before a response is interpreted; its result member cannot
  select its own meaning.

These scopes do not dictate source packaging. A conforming implementation may
keep optional behavior in ordinary role code, an adapter or a removable module
while preserving the same externally observable requirements.

The baseline does not select another named profile. It directly composes the
required mechanisms listed in Section 3. Optional profiles resolve the baseline
as their dependency; a focused mechanism selected by the baseline does not
thereby become a nested profile.

An implementation or conformance report may present that resolution as two
arrays. `requestedProfiles` contains the most-specific requested profile
identifiers and has set semantics: caller order carries no meaning and
duplicates are invalid. `resolvedProfiles` contains the de-duplicated baseline,
transitive dependencies and requested leaves in canonical dependency order.
These names describe a reporting model; they are not DCA wire members.

For the intended post-normalization period-chain name, the projection is:

```text
requestedProfiles: [dca-v1-period-chain]
resolvedProfiles:  [dca-v1-direct-https,
                    dca-v1-exact-period,
                    dca-v1-period-chain]
```

The current period-chain identifier remains `dca-period-chain-v1` until the
coordinated migration described in Section 5. The profile arrays declare
profile closure. They do not encode scope-specific selections such as supply
form, response representation, transform list or fallback permission; a claim
records those separately in the typed configuration owned by the applicable
profile.

## 3. `dca-v1-direct-https` baseline

The baseline profile is one complete direct-content-key path over HTTPS. A
conforming baseline implementation supports the portions applicable to each
role it claims.

### 3.1. Common substrate

All roles in the path implement the applicable requirements of:

- [spec--core-protocol.md](spec--core-protocol.md);
- [spec--data-format.md](spec--data-format.md);
- [spec--content-protection.md](spec--content-protection.md);
- [spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md);
- [spec--response-binding.md](spec--response-binding.md); and
- the DCA HTTPS JSON profile in
  [spec--browser-http-binding.md](spec--browser-http-binding.md).

The common cryptographic substrate is canonical unpadded base64url, ES256 for
the publisher assertion and AES-128-GCM for item protection. Each claimed role
MUST implement the operations it performs.

### 3.2. Publisher requirements

A baseline publisher:

- produces at least one protected item and a conforming ES256
  `resourceJWT`;
- implements and emits the markup carrier for baseline interchange;
- authors at least one usable direct sealed-content-key route for every item;
- implements the `ecdh-p256` publisher-to-issuer envelope; and
- emits the route using the envelope algorithm selected for that issuer.

The publisher MAY also implement object delivery and optional routes. Object
delivery is an additional declared carrier capability; it does not replace
markup when the delivery claims compatibility with a baseline-only client.
Optional routes do not replace the direct route for such a delivery.

### 3.3. Issuer requirements

A baseline issuer:

- implements ES256 publisher verification and the core processing order;
- implements the `ecdh-p256` envelope opener and direct-content-key result;
- implements direct response representation; and
- exposes a conforming DCA HTTPS JSON endpoint.

Caller authentication and business policy remain deployment choices, but the
browser-facing endpoint MUST supply an authenticated principal or an explicit
anonymous principal to policy as required by core.
An unavailable or unusable entitlement source supplies no policy decision, so
the issuer fails closed and returns no key material as core requires.

### 3.4. Client requirements

A baseline client:

- implements and accepts the markup carrier for baseline interchange and the
  core request relay;
- implements DCA HTTPS JSON with direct response admission;
- admits only response coordinates presented by its associated request;
- recognizes `contentEncodings` and fails a marked item unless it has selected
  compatible inverse transforms; and
- opens the protected item under the admitted 16-octet direct `contentKey`.

It need not implement reusable period capabilities, period chains,
client-bound custody or browser CORS.

### 3.5. Mandatory-to-implement versus selected algorithms

`ecdh-p256` is mandatory to implement for baseline publisher and issuer roles.
`rsa-oaep` is optional to implement. A deployment MAY select `rsa-oaep` for an
issuer when both publisher and issuer implement it; the algorithm is selected
by the registered issuer key and is not carried in the envelope.

Direct response representation is mandatory to implement for baseline issuer
and client roles but optional to enable for deployments that select a complete
client-bound profile. A client-bound-only deployment is conforming only when
its endpoint fails rather than silently selecting direct representation.

These rules keep one common implementation path across deployments without
forcing a deployment to use every mandatory-to-implement mechanism.

## 4. `dca-v1-browser-origin` profile

This optional profile composes the baseline with the DCA browser-origin mechanism
in [spec--browser-http-binding.md](spec--browser-http-binding.md). The
publisher, browser client, issuer endpoint and any trusted proxy implement all
requirements assigned to them there.

The publisher signs the canonical delivery origin. The browser platform
supplies the `Origin` header; a page cannot override that browser-provided
value at the trusted HTTP boundary. The issuer
requires verified signed/observed-origin equality before response-cache,
policy-decision or opening-key work and emits CORS permission only as that
profile permits.

This profile provides the stated calling-page-origin boundary. It does not
authenticate the caller, replace HTTPS issuer authentication, stop a
non-browser caller or protect against script executing in the admitted origin.

An uncredentialed browser call is the profile default. A deployment using
browser credentials additionally enables credentialed browser mode and
configures both Fetch credential mode and exact-origin credentialed CORS. That
mode is not a separately named DCA profile.

## 5. `dca-v1-exact-period` profile

This optional profile adds reusable exact period-key delivery and caching. It
depends on [spec--period-keys.md](spec--period-keys.md) and the exact-period
content-key wrapping transcript in
[spec--content-protection.md](spec--content-protection.md).

When selected:

- the publisher produces exact period capabilities at this profile's 16-octet
  width, wraps the one item `contentKey` at every emitted `(accessGroup, t)`
  with AES-128-GCM and supplies at least one issuer-mediated matching exact
  route;
- the request path relays admitted exact coordinates required by unresolved
  items and SHOULD omit coordinates already satisfied locally;
- the issuer opens and returns only presented and authorized exact leaves; and
- the client admits, scopes, stores and attempts exact candidates according to
  the period and content-protection specifications.

Every affected publisher, issuer and client role MUST implement this profile
before a deployment relies on an exact-only authoring route. For that selected
deployment, the exact route MAY replace emission of the baseline direct route;
all roles still implement the baseline mechanisms applicable to them. Such a
delivery is not baseline-compatible. An item that retains a baseline direct
route remains openable by a baseline-only client.

Selecting exact-period support does not select the period-chain profile, chain
relay, chain response acceptance, content representations, browser CORS or
client-bound custody.

### 5.1. `dca-period-chain-v1` profile

The remaining period-chain rules in this section apply only when the
period-chain profile is additionally selected and its exact-period dependency
has resolved. Exact-period alone authorizes no chain carrier, relay, issuer
processing or chain-state response.

The profile relationship is:

```text
dca-v1-direct-https                 baseline profile
└── dca-v1-exact-period             optional conformance profile
    └── dca-period-chain-v1         optional period-chain profile
```

The hierarchy states dependencies, not three key types. A direct-only
deployment selects neither optional profile. The period-chain profile depends
on the exact-period floor. Its canonical construction produces positioned
chain capability and the same exact `periodKey[t]` leaves that exact-only
issuers and clients use.

For each issuer route, the publisher may supply exact members, chain members
or both as the period-chain specification permits. Chain material beside a
complete exact supply does not require the issuer to use it. If the route omits
the exact period members and an operation relies on that period route, the
request path MUST relay the chain material and the issuer MUST accept and
process it; otherwise that route is not usable. A separately authored direct
content-key route remains an alternative and is not forced through the chain.

The omission occurs in the issuer-capability layer. The item's period route
still wraps its `contentKey` under exact `periodKey[t]` leaves. The issuer block
supplies either exact period capability, chain capability from which the same
leaves can be derived, or both.

These supply shapes do not create separate profile identifiers. Exact-only
supply is the dependency path. Exact-plus-chain supply permits transition or a
chain-capable alternative but adds publisher-delivery bytes. Only chain-only
period supply can reduce publisher-delivery bytes by replacing exact issuer
members. It requires the relay and issuer-input obligations above only when an
operation relies on that retained route. Within one chain window, extending
the authorized cutoff does not add another chain member, while exact supply
adds one member per additional period. Chain supply thus preserves fine period
granularity while its member count scales with touched windows rather than
granted periods. The actual byte saving depends on the envelope algorithm,
number of exact members replaced, number of chain windows supplied and
compression used for delivery.

A chain-input issuer MAY project authorized exact leaves into the exact-period
response, so the client need not implement chain derivation. Returning
positioned chain state selects an additional response path: the issuer MUST
emit it only for a client population and transport configured to accept it,
and that client MUST admit, retain and derive it under the period-chain rules.

The current `dca-period-chain-v1` spelling is inconsistent with the other
named DCA v1 profiles. The intended pre-v1 name is `dca-v1-period-chain`.
Until that change lands, the current spelling remains the profile identifier
and also enters its canonical construction's derivation contexts, so the
change requires new derived bytes and corresponding evidence.

Selection occurs from trusted publisher and deployment configuration before a
render is produced. Merely implementing exact-period or period-chain behavior
does not select it. When no complete exact-period issuer route is selected, the
publisher omits item period wraps and sealed period material. DCA v1 defines
no runtime issuer-capability advertisement from which a publisher can infer
selection, and a client request arrives too late to change an existing render.

### 5.2. Fixed v1 width and security positioning

DCA v1 MUST use exactly 16 octets for each delivered `contentKey`, exact
`periodKey` and positioned `periodChainKey`. Content encryption and exact
content-key wrapping use AES-128-GCM. This width applies before sealing and
after opening, including direct delivery and permitted client-bound `c`/`p`
delivery; `pc` remains forbidden on client-bound transport. A publisher, issuer
or client MUST NOT select a second width, infer a profile from length,
accept a retired width profile, or emit duplicate width-specific wrap sets.

The canonical construction fixed by the optional `dca-period-chain-v1` profile
produces the same 16-octet exact leaves consumed by Section 5. It does not
alter their width or meaning. Its publisher-retained derivation secret remains
32 octets. The internal
publisher-to-issuer P-256 shared coordinate and issuer-to-client ECDH/HKDF
transport key each remain 32-octet AES-256-GCM keys; they are not delivered
capabilities. A shared AES helper may admit both widths only after its caller
identifies the operation and validates that operation's required width.

The remainder of this subsection is informative.

One fixed width gives all producers and consumers one delivered-key contract.
Mandatory support for two widths is technically possible, but adds a conforming
state without a current requirement. Per-route selection risks incompatible
consumers; duplicate wraps increase wire cost. Neither supplies a post-quantum
property to the current public-key suite. A different width or security target
requires a new suite/specification version, not another v1 profile.

V1 targets 128-bit classical symmetric-key strength. NIST uses AES-128 key
search as its post-quantum Category 1 comparison reference; that is not a
128-bit quantum-security claim. A chain state grants a bounded window prefix,
so its disclosure reaches more coordinates than disclosure of one exact leaf.
The current P-256/RSA envelopes and ES256 signatures are not post-quantum.
A future transition needs new public-key suites and a publication/retirement
strategy; it cannot erase copied v1 artifacts or retrofit their confidentiality.
See NIST's
[post-quantum security categories](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29)
and [post-quantum FAQ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs).

A 16-octet capability encodes to 22 unpadded-base64url characters. Exact wraps
contain 16 ciphertext octets and a 16-octet tag, and P-256 publisher envelopes
are 109 decoded octets. Each AEAD-encrypted key payload therefore carries 16
raw octets of key material, in every content-key wrap and applicable issuer
envelope. RSA ciphertexts remain
modulus-wide, and article ciphertext length and tag/nonce sizes do not change.
Uniform key material is not usefully reduced by ordinary content compression.

## 6. `dca-v1-content-representations` profile

This optional profile selects the ordered `contentEncodings` mechanism in
[spec--content-protection.md](spec--content-protection.md). It changes only the
publisher and client roles; issuers and key-delivery routes are unaffected.

When selected, the publisher emits a non-empty encoding sequence only where
the deployment has established that intended clients support every named
transform. The list carried by an item is its per-item selection signal. The
client admits the entire sequence and reverses it only after successful
content authentication and decryption. Each named transform remains separately
optional and is defined by its own profile or external specification.

A delivery claiming compatibility with a baseline-only client MUST omit
`contentEncodings`. A client that has not selected compatible transforms MUST
fail a marked item; it MUST NOT expose the represented bytes as base content.

## 7. Client-bound custody profiles

The optional profiles `dca-v1-client-bound-ecdh-p256` and
`dca-v1-client-bound-rsa-oaep` select the corresponding methods in
[spec--response-binding.md](spec--response-binding.md). They layer on the HTTPS
channel and do not replace issuer authentication.

For either profile:

- the client implements and enables one method, retains its non-extractable
  private key and offers the matching public JWK;
- the issuer endpoint implements that method, admits the offer before opening
  publisher-supplied keys when client-bound delivery is required, and confirms
  selection in the response;
- every delivered content or exact period key uses the selected wrapped-leaf
  form; and
- the client admits the transport and opens each accepted leaf directly to a
  non-extractable handle with the usage assigned to its key kind.

Authenticated endpoint metadata or trusted deployment configuration states
whether client-bound delivery is required or direct fallback is permitted.
Required client-bound delivery MUST fail on an absent, unsupported or malformed
offer and MUST NOT return direct keys. A deployment that permits fallback must
establish that the client accepts direct delivery; the current request grammar
has no interoperable fallback signal.

The ECDH-P256 and RSA-OAEP methods are independent alternatives. Implementing
one does not imply the other. Neither v1 method accepts direct chain state;
client-bound `periodChainKeys` requires a future explicitly selected
byte-free expansion profile.

The `ECDH-P256` name here is the issuer-to-client client-bound method, which
uses HKDF-SHA-256. It is distinct from the publisher-to-issuer `ecdh-p256`
envelope, whose selected transcript uses the raw ECDH shared x-coordinate with
no KDF.

## 8. `dca-v1-not-delivered-result` profile

This optional profile lets an issuer report why it did not deliver a capability for
one access-group family, and lets a client read that report. It selects the
`notDelivered` core-result member in
[spec--core-protocol.md](spec--core-protocol.md#72-not-delivered-access-group-families)
and the client admission rules for it in
[spec--response-binding.md](spec--response-binding.md#3-inputs-and-common-response-form).

When selected:

- the issuer emits a `notDelivered` entry for each presented family for which its
  policy step of core Section 6.2 decided to deliver no capability, whether it
  denied the family or has no period to serve for it. Its `reason` MUST be
  `denied` for the former or `no_current_period` for the latter. If both
  conditions apply, `denied` takes precedence; `no_current_period` is used only
  when policy did not deny the family. It omits the member when it has no
  presented family for which it makes no delivery. Under the profile a
  `notDelivered` family carries neither a delivered period capability nor a
  period-coordinate `errors` entry. Independently authorized direct
  content-name results MAY coexist as core Section 7.2 specifies. A family
  without `notDelivered` remains under the core's ordinary per-coordinate
  delivery and error rules;
- the client accepts the member and admits each entry against the presented set
  of the associated request;
- the deployment settles the selection before the client interprets a response,
  in the same configuration that names the issuer endpoint and its other
  profiles; and
- neither role reads the presence of the member in a response as the selection
  signal.

The profile composes with the baseline direct-content-key path, with the exact
period-key results of Section 5 and with a period-chain result. Under each of
them the response delivers no key for a not-delivered family, and the report states
the issuer's policy outcome for that family. The profile changes no
authorization reach, adds no request member and delivers no key material. An
issuer that does not select it reaches the same policy outcome by omitting the
family from the result and saying nothing about why it is absent.

The profile discloses one policy fact per presented family to the caller: that
the issuer did not deliver it, and one of the two defined `reason` strings. The deployment that
selects the profile accepts that disclosure to the reader's browser. Under
[spec--security-model.md](spec--security-model.md#error-response-information-leakage),
the issuer MUST keep `message` coarse and disclose no key identifier, available-
period detail, entitlement detail or other caller-specific state beyond the
selected `reason`.

An admitted non-delivery is terminal for that issuer attempt. The client MUST NOT
use it to authorize a request to another configured issuer for the same
unresolved family.
[guide--unlock-fallback.md](guide--unlock-fallback.md#when-the-client-may-advance)
describes where that outcome sits in a deployment's route walk.

A client that has not selected this profile reads no non-delivery outcome from
the member. It handles the member as an unsupported section under
[spec--response-binding.md](spec--response-binding.md#3-inputs-and-common-response-form),
and that handling alone decides what its route walk does next.

## 9. Composition rules

Profiles compose only when every affected role implements and selects their
combined requirements. The rows below enumerate combinations of result kinds
and profile duties. A response-representation layer such as a client-bound
method composes independently except where a row states an exclusion.

| Combination | Status |
| --- | --- |
| baseline + browser origin | Permitted; adds Origin/CORS boundary |
| baseline + exact period | Permitted; direct and exact routes may coexist |
| exact period + `dca-period-chain-v1` profile | Permitted; the chain specification owns its canonical construction and role mechanisms, while this profile governs a selected publisher-to-issuer chain path and the additional chain-response path described in Section 5 |
| browser origin + either client-bound method | Permitted; browser request binding and response custody remain separate layers |
| exact period + either client-bound method | Permitted for exact period-key and direct content-key results; resulting keys are non-extractable handles |
| content representations + baseline, browser origin or exact period | Permitted; representation processing does not alter access authority or key delivery |
| both client-bound methods in one response | Forbidden; one offered and selected method applies to the response |
| direct and client-bound leaves in one response | Forbidden |
| client-bound method + direct chain-state result | Unsupported in v1 |
| unknown marked wrap or transform + base interpretation | Forbidden fallback |
| not-delivered result + baseline, exact period or period-chain result | Permitted; Section 8 states what each combination reports |

A profile not listed here is not automatically forbidden. An implementation
MUST NOT claim interoperability for it until the profile defines:

- its identifier, baseline relationship and dependency closure;
- every affected role and its implementation-support duties;
- the trusted facts that enable it;
- its authored alternatives, emitted results and offers, as applicable;
- the scope, timing, deciding actor or trusted fact, and signal for each
  selection;
- the representation used at every changed role boundary;
- acceptance, unsupported and refusal behavior;
- whether omission removes a fallback or leaves another complete route;
- interactions and exclusions with other profiles; and
- the scope reported by its conformance claim.

## 10. Conformance claims

A conformance claim names:

- the DCA version;
- each role implemented;
- the baseline carrier and envelope algorithms implemented;
- every named content transform implemented, and the profile or external
  specification that defines it;
- every optional profile implemented;
- every profile enabled for the deployment; and
- any external endpoint or credential profile required to complete the path.

The claim also records the requested profile leaves, their resolved dependency
closure and the selection scope for any duties that change which cross-role
path ran. For the period-chain profile this includes publisher-to-issuer supply
mode and issuer-to-client response form; naming the profile alone does not claim
that every permitted form ran.

An implementation MUST NOT claim an optional profile merely because it ignores
the profile's fields or relays them opaquely. A relay may claim only its relay
duty when the profile assigns it no interpretation work.

Passing one vector or using the reference source is not complete conformance.
Each claim requires the positive, negative, ordering and composition evidence
identified by its normative specifications.

The informative [verification overview](../verification/README.md#from-a-profile-name-to-evidence)
shows where the current primitive, vector, fixture, implementation and
composition evidence lives, which commands execute it and which named-profile
claim aggregation is not yet implemented.

## 11. Security considerations

Security depends on the distinctions defined above: implementation does not
imply enablement or selection; optional mechanisms supply their stated
guarantee only in a complete selected composition; browser-origin admission
does not authenticate the caller; and client-bound custody neither replaces
issuer authentication nor prevents authorized use. A selected profile retains
the security and failure boundaries of each mechanism it composes.

Section 5.2 explains why fixed-width v1 symmetric capabilities are not a
post-quantum claim. The [mandatory threat model](spec--security-model.md)
defines the attacker and trust boundaries used to evaluate every profile.

## 12. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [DCA core protocol](spec--core-protocol.md)
- [DCA data format](spec--data-format.md)
- [DCA content protection](spec--content-protection.md)
- [DCA publisher-to-issuer sealed-key envelopes](spec--sealed-key-envelopes.md)
- [DCA issuer-response binding](spec--response-binding.md)
- [DCA browser and HTTP binding](spec--browser-http-binding.md)
- [DCA exact period-key capabilities](spec--period-keys.md)
- [DCA period-chain construction and delegation](spec--period-key-chains.md)
- [DCA security model](spec--security-model.md)

## 13. Informative References

- [NIST post-quantum cryptography evaluation criteria](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29)
- [NIST post-quantum cryptography FAQ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs)
- [DCA unlock routing and fallback](guide--unlock-fallback.md)
