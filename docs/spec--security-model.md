# Delegated Content Access (DCA): Security Model

Status: Public Working Draft

## Abstract

This document describes the base security model of Delegated Content Access
(DCA). DCA encrypts publisher content so that reading it normally requires a
key returned through an issuer, which recreates the access boundary of a
server-side paywall while the encrypted page stays cacheable. The document
states the trust assumptions that bound the attacker and the enforcement
boundary at the issuer, including the selected browser-origin check. It lists
the attacks DCA blocks and the attacks it accepts by design, such as an
authorized reader sharing keys or plaintext, records the consequences of key
compromise, replay and error responses, and summarizes the cryptographic
primitives. DCA blocks CSS-only bypasses; it does not provide DRM.

## 1. Introduction

Following [RFC 3552](https://www.rfc-editor.org/rfc/rfc3552.html), this
document states the attacks DCA blocks, the attacks it accepts by design and
the consequences of each.

### 1.1 Scope and responsibility

This model applies to the core protocol and the profiles selected by a
deployment. A security property is conditional on its stated trust assumptions
and on the mechanisms that provide it. Selecting a profile adds its specified
obligations; it does not add every protection that could be built around DCA.

| Context | Responsibility and limit |
| --- | --- |
| Protocol and implementation | Authenticate resource claims, enforce issuer authorization and registration-scoped key use, preserve cryptographic bindings, and deliver only permitted capabilities. Implementations must also support the successful paths their selected profiles specify. |
| Selected profiles | Provide the additional protection that profile defines. Browser-origin admission and client-bound response protection apply only when selected, with their stated limits. |
| Publisher and issuer policy | The publisher chooses content, grouping and delegation; the issuer decides grants using authenticated claims and trusted policy. DCA enforces these choices without deciding whether they are commercially or editorially appropriate. |
| Deployment operations | Provision trusted registrations, protect secrets, configure endpoints and maintain the implementations. Protocol requirements on these operations still apply; protection after a trust root is compromised is limited as described below. |
| Accepted capability use | Authorized readers can use and share plaintext or keys within their cryptographic reach. Later policy changes cannot retract material already delivered. |

A protocol defect permits behavior contrary to one of these specified
obligations while its assumptions hold. An implementation defect violates an
obligation, including a required validation or successful opening path.
Neither is excused by calling it a deployment concern. Conversely, a choice
left to the content owner or issuer, an accepted limitation, or additional
protection after a trust assumption fails does not by itself establish a
missing protocol requirement.

These boundaries do not promise uninterrupted service, protection from arbitrary
resource exhaustion, or factual verification of publisher-authored claims.
The specified input limits, refusal behavior and authorization checks remain
applicable; deployments choose additional availability and abuse controls.

<a id="design-goal"></a>
## 2. Design goal

**DCA blocks CSS-only bypasses but does not provide DRM.**

DCA blocks CSS- or markup-only bypass: reading content requires a key that an
issuer approved, which recreates a server-side paywall's boundary while the
encrypted page stays cacheable and issuer-independent. It does not stop an
authorized reader, or code that runs with that reader's access in a browser, a
native application or a server, from sharing the key or copying plaintext.

<a id="trust-assumptions"></a>
## 3. Trust assumptions

The publisher's render-signing key and secret content-key material, and each
entrusted issuer's private key, are trust roots. Their theft is an operational
key compromise, not an attack the base DCA protocol is required to withstand.
The same assumption applies to secret period-key and derivation material used
by selected profiles. Each profile defines that material's cryptographic reach.
The [period-key profile](spec-profile--period-keys.md) consumes opaque
`periodKey` values supplied for their coordinates; the
[chain-key profile](spec-profile--chain-keys.md) additionally defines bounded
chain derivation and the reach of its publisher-retained `keyDerivationSecret`.

On suspected signing-key compromise the publisher rotates the key and issuers
retire the old verification key. An issuer then refuses every new request that
relies on a render signed only by the retired key
([core Section 4.2](spec--core-protocol.md#42-verification-and-registration));
keys and plaintext a client already holds stay usable
([Section 8.2](#replay-limits)).

The publisher controls its own content, grouping, signed resource claims and
choice of entrusted issuers. DCA does not protect that content from its owner's
decision to disclose it or delegate broad access. Signature verification
establishes who made the claims and that they have not changed; it does not
establish their factual truth. Which authenticated claims an issuer accepts
for its access decisions is part of its trusted registration and policy.

The issuer's ordinary duties enforce the access boundary for every request:
verify the resource claims, apply its own authorization policy, resolve keys
within the verified publisher registration, and release only permitted
capabilities. These duties do not depend on a judgment about the publisher's
intentions. A request under registration A cannot select a private key available
only under registration B
([core Section 6.3](spec--core-protocol.md#63-opening-key-scope-and-bind)).
Publishers sharing an opening keyset are mutually trusted within that
cryptographic entrustment domain, as Section 4 explains.

An untrusted caller may control its client, whether a browser, native
application or server process, and use its own credentials, copied public
markup and relabelled request fields. The attacker does not begin with a
trusted party's secret key. Those inputs must pass the same verification,
authorization and binding checks. Publisher responsibility does not excuse
implementation defects that bypass those checks or prevent an entitled reader
from opening content through a permitted path.

<a id="enforcement-boundary"></a>
## 4. Enforcement boundary

DCA is not a soft paywall. A soft paywall ships readable content and hides it
with client-side presentation logic. DCA ships encrypted content and requires
issuer-approved key delivery, mimicking a server-side paywall on the client.
A reader who has neither access nor shared access cannot reveal the article
with a CSS or DOM change. This is separate from reader-to-reader sharing.

Readers can already share access to a server-side paywall by sharing a login,
session cookie or bearer token, or by proxying an authenticated session. A DCA
response in direct transport mode has a comparable sharing boundary: whoever
copies the returned key bytes can use them within their reach. Client-bound
transport mode encrypts each returned key for one recipient key that the
client offered, so a copied response is unusable without that recipient
private key. It does not stop the reader who controls that client
([Section 5](#choosing-the-operating-boundary)).

When the issuer opens publisher-sealed material, it rebuilds BIND
([core Section 6.3](spec--core-protocol.md#63-opening-key-scope-and-bind)).
BIND protects coordinate integrity; it
neither prevents sharing nor protects the issuer's response. The selected
[response binding](spec--response-binding.md#2-layered-security-model)
protects delivery from issuer to client.

A contentKey returned by the issuer opens one item. A periodKey opens every
item wrapped under its publisher-scoped `accessGroup` for that period; the
client uses it to unwrap each item's contentKey. An issuer returns the item's
contentKey when its decision is narrower than the whole group. Wraps under
several groups are OR alternatives
([period keys Section 6.1](spec-profile--period-keys.md#61-assigning-access-groups-before-sealing));
the publisher chooses the reach and caching trade-off when it authors them, and
conjunction needs a separately authored coordinate or an item `contentKey`
returned by the issuer. What the publisher entrusts to each issuer, and why a
supplied period key reaches items outside that issuer's item selection, is
defined in [core Section 2.1](spec--core-protocol.md#21-publisher).

**Issuer-decision invariant.** The client controls the unsigned unlock
request, including the `sealed` maps. The client names coordinates with those
maps; only the issuer decides grants. The
issuer makes every entitlement, meter and policy decision from verified
`resourceJWT` claims plus issuer-held identity, configuration and state; it
then opens only sealed values whose use that decision permits
([core Section 6.3](spec--core-protocol.md#63-opening-key-scope-and-bind)). An
issuer that grants on presentation alone defeats the access boundary even when
BIND verifies.

Client relay selection is not authorization. Omitting publisher-authored
material can remove a usable alternative, and presenting another authored
alternative can waste request bytes or issuer work; neither action selects a
profile or widens a grant. A carried configuration that changes issuer
interpretation becomes trusted only through a verified publisher commitment
or issuer-held configuration, never through its presence in the unsigned
request.

The client fallback rules in
[core Section 5.3](spec--core-protocol.md#53-multiple-issuers) are
coordination among conforming clients in the same sense. They say when a
client that follows its route configuration may offer an unresolved
coordinate to another issuer. They do not stop a reader from submitting a
request to any issuer independently, and each issuer authorizes every request
it receives on its own verified claims and policy.

Under a selected `dca-profile-browser-origin` binding, the issuer compares the
`Origin` it observes at its trusted TLS or proxy boundary byte for byte with
the canonical origin in the verified `resourceJWT`
([HTTP binding Section 3.2](spec--http-binding.md#32-canonical-signed-origin),
[browser-origin Section 2.3](spec-profile--browser-origin.md#23-post-admission-order))
before it authorizes access, consults a response cache or opens publisher
envelopes.

That verified origin, not an unsigned request field, is the policy coordinate
([core Section 6.2](spec--core-protocol.md#62-authentication-and-policy)), and only
that origin receives CORS permission.

A preflight carries no `resourceJWT`, so the endpoint cannot compare origins
there. It applies its preflight origin policy to the canonical observed `Origin`;
syntax alone does not satisfy that policy. A successful preflight grants no DCA
authority and predicts no successful `POST`
([browser-origin Section 2.5](spec-profile--browser-origin.md#25-preflight)).

The origin check stops a copy site from using a visitor's browser as a
key-opening oracle: the copy serves the render from its own origin, the browser
reports that origin, and it differs from the one the publisher signed. It does
not authenticate an arbitrary HTTP client, which can forge `Origin` and replay
the signed JWT unchanged. Non-browser callers need a separate authenticated
binding.

The signed origin does not isolate registered publishers that share one issuer
opening keyset: such a publisher signs its own `resourceJWT` for its own origin
while copying the other's sealed value and `renderId`, and the issuer opens it
with the key both were sealed to. Publishers sharing one opening keyset are
therefore mutually trusted. Mutually untrusted publishers need separate opening
keysets ([sealed-key envelopes](spec--sealed-key-envelopes.md) Section 7), and
lookup of the unsigned `issuerName`/`keyId` pair stays inside the verifying
registration
([core Section 6.3](spec--core-protocol.md#63-opening-key-scope-and-bind)),
because accepting another publisher's copied `keyId` would select its private
key.

Aliases whose opening-key entries resolve to one private key are one
cryptographic entrustment domain: every holder of that key can open what is
sealed to it under any alias. Core Sections
[2.1](spec--core-protocol.md#21-publisher) and
[6.3](spec--core-protocol.md#63-opening-key-scope-and-bind) state the
publisher's duty and the lookup scope.

<a id="choosing-the-operating-boundary"></a>
## 5. Choosing the operating boundary

Render and slot binding protect integrity against substitution; they are not an
anti-sharing control. Which capability the issuer returns, a reusable period
key or a per-item content key, is a choice about online control, reuse and cost;
[deployment patterns](guide--deployment-patterns.md) compares them.


One authorized reader is enough to redistribute a key capability or plaintext.
Client-bound transport raises the effort for passive response copying, but a
reader controlling the browser needs no root access: they can submit their own
extractable client key before the honest scripts run, use an honest handle as
an oracle, proxy operations, or share the decrypted content. A native or
server client holds its keys in its own process, and whoever controls that
process has the same options.

Issuer-side account, rate, concurrency, IP or network checks can add friction,
detection and revocation. They do not make a client-held key or rendered
plaintext unshareable, and they can reject legitimate travel, VPN or shared
network use. Treat them as deployment policy, not as a DCA guarantee; DCA
specifies no rate-limit algorithm.

<a id="what-dca-protects-against"></a>
## 6. What DCA protects against

| Attack | Protection | How |
|--------|------------|-----|
| CSS- or markup-only bypass | **Blocked** | Protected content is AES-128-GCM ciphertext, and no element holds the plaintext. |
| Unentitled coordinate or request presentation | **Blocked at the issuer** | Unsigned request fields grant nothing ([Section 4](#enforcement-boundary), issuer-decision invariant). |
| Copied delivery used as a key-opening oracle on another site | **Blocked by selected browser-origin admission** | The issuer compares the observed browser Origin with the verified signed `origin` claim (core Section 4.1) before policy or key opening. A baseline-only non-browser path needs its own trusted caller and credential binding; baseline conformance alone supplies no browser-origin protection. |
| Offline opening of issuer-sealed material | **Blocked while issuer keys remain secret** | The opening key stays at the issuer; possession of a public envelope or its coordinates grants nothing. |
| Automated or bulk acquisition | **Authorization-gated, not prevented** | Each missing key requires an issuer grant. An authorized reader can automate acquisition, and one period key opens every retained matching item. |
| Request or response replay | **Scope-bounded, not prevented** | A repeated request reaches current issuer policy. A captured successful key remains usable for retained ciphertext at the coordinates it covers. |
| Content-key substitution between articles | **Blocked at the issuer** | BIND ties each item content key sealed for the issuer to its signed render and content name. This is separate from period-key reuse within an access group. |

<a id="what-dca-does-not-protect-against"></a>
## 7. What DCA does not protect against

These are **accepted, by design**. Each is something an authorized reader, or
code acting with that reader's access, does with capability the issuer
actually granted:

| Attack | Why it's accepted |
|--------|-------------------|
| Authorized user copies decrypted text | Not DRM. As with any paywall, the user can screenshot, copy/paste or share. |
| Reader shares returned access or key material | Direct transport mode is comparable to sharing a login, session cookie or bearer token. Client-bound transport mode makes a copied response unusable without the recipient private key, but the reader who controls the client needs no root access to use or relay the access. |
| Script, extension or application code reads plaintext after opening | Plaintext must reach the application or DOM to be used. Code that runs with the reader's access there can read it. |

An issuer opening-key leak lets its holder open every value sealed for that
key. That is a trust-root compromise ([Section 3](#trust-assumptions)), not
reuse of a granted capability; rotation and a separate opening keyset per
mutually untrusted publisher limit its reach.

<a id="limitations-and-consequences"></a>
## 8. Limitations and consequences

<a id="client-held-decryption-keys"></a>
### 8.1 Client-held decryption keys

The host performing the DCA client role, a browser page, a native application
or a server or edge process
([deployment patterns](guide--deployment-patterns.md)), needs a usable key to
open content. Direct transport exposes raw key bytes. Client-bound transport
opens content and period keys to non-extractable handles and leaves a chain key
usable as bytes
([response binding Sections 4 and 6](spec--response-binding.md#4-selection-and-agreement)).
A derivation key a selected profile defines, such as a content-group chain or
period key, also stays usable as bytes.
Non-extractability prevents `exportKey`, not use or structured cloning by
script that can reach a handle.

**Boundary**: Whoever controls the client can use the keys and handles it
reaches and can copy plaintext ([Section 5](#choosing-the-operating-boundary)).
Resistance to a compromised device, browser or server host is outside the
base model.

<a id="replay-limits"></a>
### 8.2 Replay limits

A captured unlock response carries the keys the issuer returned for its
coordinates: item content keys, period keys or, under the optional
extension, chain keys. In direct transport mode whoever holds the capture
holds those key bytes. A captured client-bound response supplies no usable
key by itself; opening it takes the recipient private key. A period key
obtained this way opens any matching ciphertext whose item content key is
wrapped under the same period-key bytes for its publisher, access group and
period coordinate, including ciphertext produced after the grant. A period
rollover prevents it from opening renders sealed solely under later labels, and a new
family generation keeps it out of later renders at the same labels
([spec-profile--period-keys.md](spec-profile--period-keys.md#base-period-key-requirements)).
Neither step, nor key retirement or a later loss of entitlement, revokes a
delivered key: it still opens any ciphertext matching its reach, whether
already retained or obtained later
([period keys Section 11](spec-profile--period-keys.md#capability-lifecycle)).

**Consequence**: Replaying the response does not widen the coordinates it
already granted. A chain key reaches back through its window to the window
start by design
([chain keys Section 5.3](spec-profile--chain-keys.md#capability-reach)).

<a id="publisher-signing-key-compromise"></a>
### 8.3 Publisher signing-key compromise

DCA treats the publisher's signing key as a trust root. Its compromise
lets an attacker forge publisher-signed resource claims, but does not reveal an
issuer private key, independently supplied period-key material, or
plaintext by itself;
key delivery still passes through an issuer's policy and opening operation.
Containing that compromise, for example by keeping browser origins in
issuer-held registration, may reduce blast radius, but is defense in depth,
not a base-protocol requirement under this security model.

**Model boundary**: the signing key is a trust root
([Section 3](#trust-assumptions)).

<a id="error-response-information-leakage"></a>
### 8.4 Error-response information leakage

Different externally visible failures can become a probing oracle. Envelope
opening exposes one generic failure
([sealed-key envelopes](spec--sealed-key-envelopes.md#6-opening-and-failure)
Section 6), failure detail stays within
[core Section 8](spec--core-protocol.md#8-failure-model), and the HTTPS endpoint
binding recommends coarse bodies
([HTTP binding Section 4](spec--http-binding.md#4-security-considerations-failures-and-privacy)). A
`notDelivered` reason
([period keys Section 5.6](spec-profile--period-keys.md#56-family-reports-notdelivered))
tells the caller, including a browser reader, whether a presented family was
denied or unavailable; the deployment accepts that disclosure.

<a id="what-opening-proves"></a>
### 8.5 What opening proves

Opening an item verifies its ciphertext under the held content key, the
implicit twelve-zero-octet nonce and content AAD built from the delivery's
`renderId` and item name. A complete item record moved to another slot or render therefore fails, even when
a cached period key recovers the content key without contacting an issuer.
The tag does not bind type, encoding list or other JWT claims. Altering such
admitted metadata can change handling or decoding without authentication
failure or a new key grant. Opening shows neither publisher authorship nor
page placement: a holder of the content
key can build another valid tuple
([content protection Sections 3.2 and 9](spec--content-protection.md#32-content-aad)).
The following cases require separate consideration:

- **A detached copy.** A saved or forwarded delivery opens under a held key
  wherever the client finds it. A successful opening says nothing about where
  that copy came from.
- **Signed resource claims.** `resourceJWT` authenticates the publisher's
  claims to the issuer, which verifies it under the registered signing key. A
  baseline client need not verify it. The client decodes and admits `renderId`
  for content AAD; other claims and token spelling are outside that tag. A
  decoded but unverified payload supplies no publisher identity or origin
  ([core Section 2.2](spec--core-protocol.md#22-client),
  [Section 4.2](spec--core-protocol.md#42-verification-and-registration)).
- **Trusted source retrieval.** A client that must know where a delivery came
  from, such as a server client whose output reaches other readers,
  establishes that itself by retrieving the delivery from a source it trusts.
  The selected DCA profiles leave this retrieval procedure to the client.

<a id="industry-context"></a>
## 9. Industry context

DCA applies an established envelope-encryption pattern;
[deployment patterns](guide--deployment-patterns.md#how-this-relates-to-familiar-deployments)
compares it with familiar deployments.

<a id="cryptographic-primitives"></a>
## 10. Cryptographic primitives

The following core mechanisms use standard cryptographic primitives available
through WebCrypto. Selected profiles define their additional constructions and
security considerations in their own specifications:

| Operation | Primitive | Defined in |
|-----------|-----------|------------|
| Content encryption | AES-128-GCM | content protection Section 3 |
| Period key wrapping a content key | AES-128-GCM under a 16-octet period key | content protection Section 4; period keys Section 6.2 |
| Publisher-to-issuer ECDH envelope | P-256 ECDH raw 32-byte shared x-coordinate + AES-256-GCM | sealed-key envelopes Section 4 |
| Publisher-to-issuer RSA envelope | RSA-OAEP with SHA-256 | sealed-key envelopes Section 5 |
| Optional issuer-to-client transport | Selected response-binding profile | response binding Sections 6-8 |
| Resource signing | ES256 (ECDSA P-256) | core Sections 4.1-4.2; browser-origin Section 2.3 |

Delivered `contentKey`, `periodKey` and positioned `chainKey` values are 16
octets in v1 ([sealed-key envelopes](spec--sealed-key-envelopes.md) Section 2),
a 128-bit classical symmetric-key target. One fixed width gives every producer
and consumer one delivered-key contract and saves bytes in every wrapped
payload; another width or security target needs a new suite version
(sealed-key envelopes Section 2). NIST uses AES-128 key search as its
post-quantum
[Category 1](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29)
comparison reference
([FAQ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs)); that is
not a 128-bit quantum-security claim.

V1 is not post-quantum: its P-256/RSA envelopes and ES256 signatures would need
replacement, and a migration cannot protect copied v1 artifacts. A disclosed
chain key reaches its window prefix
([chain keys Section 24.1](spec-profile--chain-keys.md#capability-monotonicity)), a
period key one coordinate.

## 11. Normative References

- [DCA core protocol](spec--core-protocol.md)
- [DCA sealed key envelopes](spec--sealed-key-envelopes.md)
- [DCA HTTP binding](spec--http-binding.md)
- [DCA browser-origin profile](spec-profile--browser-origin.md)
- [DCA response binding](spec--response-binding.md)
- [DCA content protection](spec--content-protection.md)
- [DCA period-key capabilities](spec-profile--period-keys.md)
- [DCA chain keys: construction and delegation](spec-profile--chain-keys.md)

## 12. Informative References

- [RFC 3552: Guidelines for Writing RFC Text on Security Considerations](https://www.rfc-editor.org/info/rfc3552)
- [NIST post-quantum security categories](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29)
- [NIST post-quantum cryptography FAQ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs)
- [DCA deployment patterns](guide--deployment-patterns.md)
