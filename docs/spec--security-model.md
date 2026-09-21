# Delegated Content Access (DCA): Threat Model

Status: Public Working Draft

Optional deployment controls do not alter this base threat model.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) when, and only when, they
appear in all capitals.

## Design goal

**DCA blocks CSS-only bypasses but does not provide DRM.**

DCA encrypts content so reading it normally requires a key returned through an issuer. It recreates the access boundary of a server-side paywall while keeping the encrypted page cacheable and decrypting it in the client. It does not prevent a reader who has that key or the decrypted content from sharing either one.

The goal is to block CSS- or markup-only bypass and require issuer-approved key
acquisition while keeping encrypted delivery cacheable and issuer-independent.
It does not stop an authorized reader or script-capable browser from copying
plaintext.

## Trust assumptions

In ordinary terms, the publisher must protect its signing key and key source,
and each issuer must protect its opening private key. Theft of one of those
secrets is an operational key compromise, not a bypass that base DCA promises
to contain.

The honest publisher's render-signing key and exact period-key material, and
each honest issuer's private key, are trust roots. Their theft is an operational
key compromise, not an attack the base DCA protocol is required to withstand.
Base consumes opaque, independently supplied exact `periodKey` values. It
defines neither a publisher derivation secret nor a derivation from one
period's key to another. [spec--period-key-chains.md](spec--period-key-chains.md)
defines the optional extension's bounded construction and the compromise reach
of its publisher-retained `keyDerivationSecret`.

Containment, isolation and rotation consequences are recorded here; they do
not by themselves establish a base wire or boundary requirement.

On suspected publisher-signing-key compromise, the publisher rotates the key
and issuers retire its old verification key. Renders signed only by the retired
key then stop unlocking, including cached renders; that availability cost is
incident response, not a reason to grant a compromised key continuing
authority.

This does not make every registered party honest. A registered malicious
publisher, an untrusted reader controlling its browser, copied public markup,
relabelled request fields, and cross-tenant use of authority a party was
actually given remain in scope. The attacker may use its own credentials and
every public artifact but does not begin with an honest party's secret key.

## Enforcement boundary

DCA is not a soft paywall. A soft paywall ships readable content and hides it
with client-side presentation logic. DCA ships encrypted content and requires
issuer-approved key delivery, mimicking a server-side paywall on the client.
A reader who has neither access nor shared access cannot reveal the article
with a CSS or DOM change. This is separate from reader-to-reader sharing.

Readers can already share access to a server-side paywall by sharing a login,
session cookie or bearer token, or by proxying an authenticated session. Direct
DCA delivery has a comparable sharing boundary. Client-bound delivery makes
copying returned access harder by tying it to the browser, but a rooted or
otherwise modified browser can still use or relay that access. BIND binds the
issuer's answer to its decision; it does not address sharing.

A direct contentKey opens one item. A periodKey opens every item wrapped under
its publisher-scoped `accessGroup` for that period; the browser uses it to
unwrap each item's contentKey. An issuer returns the direct contentKey when its
decision is narrower than the whole group. If the publisher wrapped an item
under several groups, those are alternative (OR) routes: any one such periodKey
opens it. The publisher chooses the reach/caching trade-off when it authors
wraps; conjunction needs a separately authored coordinate or direct delivery.

The A/B binding case concerns direct delivery only: a request granted A's
contentKey must not return B's contentKey. BIND distinguishes the two with
`renderId` and `contentName`. The issuer rebuilds BIND from those fields, so its
answer matches its decision; BIND does not try to stop a cooperating reader
from sharing access.

**Issuer-decision invariant.** The browser controls the unsigned unlock
request, including the `sealed` maps. The client names coordinates with those
maps; only the issuer decides grants. The
issuer makes every entitlement, meter and policy decision from verified
`resourceJWT` claims plus issuer-held identity, configuration and state; it
then rebuilds BIND from the same requested coordinate it decided on. An issuer
that grants on presentation alone defeats the access boundary even when BIND
verifies.

Client relay selection is not authorization. Omitting publisher-authored
material can remove a usable route, and presenting another authored
alternative can waste request bytes or issuer work; neither action selects a
profile or widens a grant. A carried configuration that changes issuer
interpretation becomes trusted only through a verified publisher commitment
or issuer-held configuration, never through its presence in the unsigned
request.

The exact-origin requirement follows the browser protection boundary in
[RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html#section-3.2) and the
[WHATWG URL Standard](https://url.spec.whatwg.org/#concept-url-origin): it is
scheme, host and port, not organizational identity or a registrable domain.

For a browser unlock under a selected `dca-v1-browser-origin` binding, the
issuer application MUST:

- treat `resourceJWT` header `kid` as an untrusted key-selection hint, and
  resolve one configured verification key or one key from a trusted JWKS
  source, refusing an unknown or ambiguous lookup;
- verify the exact `resourceJWT` with that key;
- require the HTTP `Origin` observed at the issuer's trusted TLS/proxy boundary
  to equal the verified `resourceJWT.origin`, byte for byte, before policy, a
  cached answer or opening submitted key material;
- use that verified origin as the policy coordinate, and resolve unsigned
  `issuerName`/`keyId` only inside the opening-key namespace of the
  registration whose key verified the token;
- return CORS permission only for that exact origin.

An issuer that also keeps a registered origin limit per publisher may refuse an
origin that registration does not list. That limit is defense in depth, and the
issuer compares the admitted signed origin with the observed origin.

This browser-profile property belongs to the complete issuer composition, not
to DCA crypto core.
[spec--browser-http-binding.md](spec--browser-http-binding.md) specifies the
selected HTTP checks and ordering. The reference supplies a reusable
adapter outside core; a host may replace it only with equivalent behavior.

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
therefore mutually trusted. Mutually untrusted publishers receive separate
issuer opening keysets, and lookup of the unsigned `issuerName`/`keyId` pair
stays scoped to the registration whose key verified the token, because
accepting another publisher's copied `keyId` would select its private key.

The three responsibilities stay separate. For browser delivery, the issuer
compares `resourceJWT.origin` with the observed `Origin`; `renderId` with the
slot fields supplies sealed-value coordinate integrity. Registration and
opening-key scope isolates publishers.

### Origin at the HTTP boundary

The issuer's HTTP host decides what counts as the observed `Origin`, and does
so before it reaches DCA work:

- A TLS terminator or reverse proxy in front of the issuer either passes the
  browser's `Origin` header through unchanged, or strips any client-supplied
  internal forwarding header and writes its own observation. The backend reads
  that internal header only from the configured proxy address and reads the
  plain `Origin` header otherwise.
- Exactly one `Origin` header value reaches the comparison. The issuer refuses
  a request carrying the header more than once or one comma-joined value.
- A missing `Origin`, the value `null`, a value that does not parse as
  `scheme://host[:port]`, and a value carrying userinfo, a path, a query, a
  fragment or whitespace are each refused. So is any value whose bytes differ
  from the verified `resourceJWT.origin`.
- The issuer performs every refusal above before response-cache lookup, policy,
  or any private-key operation and returns no key material. Coarse failure
  bodies are recommended. A deployment that claims
  registration or origin privacy makes these pre-policy refusals externally
  uniform; the browser-origin mechanism does not require that of every
  implementation.

CORS on the unlock endpoint follows from the same value:

- The issuer sets `Access-Control-Allow-Origin` to that one exact origin,
  never `*` and never a list, and sets `Vary: Origin`. A key-bearing response
  carries `Cache-Control: no-store` under the browser binding, so `Vary: Origin`
  protects refusals, explicitly cacheable profiles and misconfigured
  intermediaries; it does not make ordinary caching of key-bearing responses
  acceptable.
- The `OPTIONS` preflight carries no JWT, so the issuer admits a syntactically
  valid origin and answers with `Access-Control-Allow-Methods: POST` and
  `Access-Control-Allow-Headers: Content-Type`. The `POST` performs the
  verified equality check before any useful work, so preflight admission grants
  nothing.
- An issuer whose authentication uses its own session cookies adds
  `Access-Control-Allow-Credentials: true`, which requires the exact origin
  the endpoint already returns.

Under signed origin a publisher starts serving a new origin without an issuer
configuration change, and retiring an old one stays an operation the issuer
runs. Renders signed for the old origin keep unlocking there while they are
cached and while their signing key is still accepted. To stop the old origin,
the publisher and issuer use a maximum render age, an issuer-side denylist of
retired origins, or a separate signing key per origin that can be retired on
its own.

## Choosing the operating boundary

One authorized reader is enough to redistribute a key capability or plaintext.
Client-bound transport raises the effort for passive response copying, but a
reader controlling the browser needs no root access: they can submit their own
extractable client key before the honest scripts run, use an honest handle as
an oracle, proxy operations, or share the decrypted content. Render/slot
binding protects integrity against substitution; it is not an anti-sharing
control.

The product choice is therefore about online control, reuse and cost:

| Operating choice | Publisher page caching | Issuer contact | Reach after delivery | Main cost / limit |
| --- | --- | --- | --- | --- |
| Cached `periodKey` | shared encrypted pages remain cacheable | once per applicable period/cache miss | the granted access group and period | least issuer traffic; broadest reusable key |
| Direct `contentKey` | shared encrypted pages remain cacheable | each unresolved render | that content item and render | more issuer traffic and availability dependence; plaintext can still be shared |
| Traditional server gating | personalized/plaintext delivery commonly reduces shared caching | each protected request | server decides before each delivery | more origin/edge complexity and cost; login, session, proxy and plaintext sharing still remain |
| Attested DRM or forensic controls | separate product architecture | product-specific | product-specific | outside DCA; higher platform, operational and user cost |

If a deployment uses the
[optional period-chain profile](guide--period-key-chains.md), its
direct `periodChainKeys` result changes how a reusable period capability is
represented; the issuer still decides the grant. From a returned cutoff, the
client derives only exact period keys at or before that cutoff within its
supplied dated window;
the issuer calculates the cutoff from verified claims, issuer policy and one
issuer-owned instant, then clamps it to publisher-supplied positioned states.
That clamp stays within the supplied state at that instant; it never relocates
the chain anchor into another window or across an absent member. See the
[period-chain issuer-selection rules](spec--period-key-chains.md#13-issuer-decision-and-response).
The client-bound profile forbids returning chain bytes. A cache retains
whatever capability was already
delivered until its host evicts it, so loss of entitlement cannot claw back
prior exact or chain reach; it can only stop a later grant.

That backward reach is deliberate. A chain key at T20 authorizes every earlier
position in its bounded window
through T20. Useful content reach is the
intersection of those derivable period keys and the encrypted artifacts that
are still available under them. A publisher may therefore choose a chain
window wider than its content-cache horizon: the publisher accepts that reach
because no useful artifact remains there. If older artifacts do
remain available and must be excluded from a grant, the publisher or issuer
uses exact period keys or a separately bounded chain window; it must not treat
the cutoff as hiding earlier positions in that window.

Issuer-side account, rate, concurrency, IP or network checks can add friction,
detection and revocation. They do not make a browser-held key or rendered
plaintext unshareable, and they can reject legitimate travel, VPN or shared
network use. Treat them as deployment policy, not as a DCA guarantee.

If a deployment needs the issuer consulted for every render, use direct
`contentKey` delivery and avoid reusable period grants; encrypted publisher
markup can still remain CDN-cacheable. If the requirement is continuous server
control or prevention of copying by an authorized reader, DCA is not the
solution. The deployment is choosing a less cacheable, more expensive delivery
architecture, or a DRM/attestation product, for a different threat model.

### Why disclose the limitation

DCA is an open protocol, so its public specification must describe the
capability and consequence: a reader-controlled client can substitute its own
client key, relay key operations, or redistribute plaintext. Hiding that fact
does not protect an implementation; a reader who can modify the request can
discover it. Hiding it stops publishers and issuers from making informed
choices about caching, online control and cost.

The specification and deployment guidance document the durable threat and
remaining risk, not a brittle recipe tied to one script or function name.
Reproducible
mechanics belong in the reference tests and separately labelled platform
evidence, where engineers can inspect the boundary without mistaking an
accepted outcome for a protocol failure. This follows ordinary open-standards
practice: document protected,
susceptible and out-of-scope attacks, including accepted or transferred risk
([RFC 3552](https://www.rfc-editor.org/rfc/rfc3552.html),
[W3C Threat Modeling Guide](https://www.w3.org/TR/threat-modeling-guide/)).

## What DCA protects against

| Attack | Protection | How |
|--------|------------|-----|
| CSS- or markup-only bypass | **Blocked** | Protected content is AES-128-GCM ciphertext, and no element holds the plaintext. |
| Unentitled coordinate or request presentation | **Blocked at the issuer** | Unsigned request fields grant nothing; the issuer decides from verified publisher claims plus issuer-held identity, configuration and state. |
| Offline opening of issuer-sealed material | **Blocked while issuer keys remain secret** | The opening key stays at the issuer; possession of a public envelope or its coordinates grants nothing. |
| Automated or bulk acquisition | **Authorization-gated, not prevented** | Each missing key requires an issuer grant. An authorized reader can automate acquisition, and one period key opens every retained matching item. |
| Request or response replay | **Scope-bounded, not prevented** | A repeated request reaches current issuer policy. A captured successful key remains usable for retained ciphertext at the coordinates it covers. |
| Direct-key substitution between articles | **Blocked at the issuer** | BIND ties each direct key to its signed render and content name. This is separate from period-key reuse within an access group. |

## What DCA does not protect against

These are **accepted, by design**:

| Attack | Why it's accepted |
|--------|-------------------|
| Authorized user copies decrypted text | Not DRM. As with any paywall, the user can screenshot, copy/paste or share. |
| Reader shares returned access or key material | Direct delivery is comparable to sharing a login, session cookie or bearer token. Client-bound delivery raises the effort, but a rooted or modified browser can still use or relay the access. |
| JS hooks reading DOM post-decrypt | Plaintext must reach the DOM to render. A sufficiently determined extension can read it. |
| Issuer key compromise | If the issuer's private key leaks, they can unlock any content sealed for them. This is true of any asymmetric system. Mitigation: key rotation, key isolation per issuer. |

## Limitations and consequences

### Client-held decryption keys

Client-side decryption requires a usable browser capability. Direct delivery
exposes raw key bytes before the client imports them; client-bound delivery can
instead produce a non-extractable `CryptoKey`. Non-extractability prevents
`exportKey`, not use or structured cloning by script that can reach the handle.

**Boundary**: A reader-controlled browser can use reachable key handles and
copy plaintext. Rooted-device and browser-compromise resistance is outside the
base model.

### Replay limits

A captured unlock response contains exact periodKeys for the coordinates the
issuer returned. Those keys continue to open retained ciphertext sealed under
those same publisher, access-group and period coordinates. A rollover only
prevents them from opening renders sealed solely under later labels.

**Consequence**: Replaying the response does not widen the coordinates it
already granted. A period-chain grant can deliberately reach a bounded set of
earlier periods; that separate reach is defined by the optional extension.

### Unlock-endpoint rate limiting

DCA specifies no rate-limit algorithm. Deployments must enforce finite request
and resource limits at the issuer boundary. The browser binding specifies the
HTTPS request and admission ordering, while authentication, entitlement and
rate-limit policy remain deployment-selected. The issuer can count key grants
but not later cached-key use or plaintext copying. Limits are only as
durable as the identity they count. Deployments choose that identity, their
accounting rules, and what happens when a limit is reached.

### Period-key compromise

Disclosure of one exact periodKey exposes ciphertext sealed for its coordinate.
No base operation derives another period's key from it. Compromise of an
external key supplier has the reach of that supplier's own construction. The
optional period-chain extension separately defines the bounded cross-period
reach of its `keyDerivationSecret` construction.

**Boundary**: Base does not turn one disclosed periodKey into authority
over other periods. Implementations still have to protect the key source they
choose, and extensions account for any wider compromise reach they introduce.

### Publisher signing-key compromise

DCA treats the honest publisher's signing key as a trust root. Its compromise
lets an attacker forge publisher-signed resource claims, but does not reveal an
issuer private key, independently supplied exact period-key material, or
plaintext by itself;
key delivery still passes through an issuer's policy and opening operation.
Containing that compromise, for example by keeping browser origins in
issuer-held registration, may reduce blast radius, but is defense in depth,
not a base-protocol requirement under this threat model.

**Why it's accepted**: Operational key protection, rotation and incident
response remain required. DCA's mandatory boundary is evaluated while the
configured trust roots are controlled by their owners.

### IV and nonce reuse

**Content encryption**: each content key is independently generated per item
and render, and the publisher samples a fresh 96-bit nonce for every
encryption. Repeating a nonce
under different independent keys does not repeat the AES-GCM key/nonce pair.
Production generators and profile invocation bounds still apply; random
sampling makes collision improbable, not impossible.

**Exact-period wrapping** (`contentData[contentName].keys`): each entry samples
a fresh 96-bit nonce, but one exact period key is reused by design across many
items and renders. Its random-bit-generator-based AES-GCM invocation count
therefore accumulates across every node, restart, replacement and backfill that
uses those key bytes. The publisher must enforce the selected profile's
aggregate bound; it must not claim that nonce reuse is impossible.

All content and wrap nonces are produced by the publisher and carried in the
delivery. The client does not derive them.

### Error-response information leakage

Different externally visible failures can become a probing oracle. The issuer
must use the generic opening failure required by
[the sealed-envelope specification](spec--sealed-key-envelopes.md#6-opening-and-failure),
and the browser binding requires unauthenticated and unauthorized bodies to be
coarse enough not to expose sensitive policy state.

## Industry context

DCA applies an established envelope-encryption pattern: the publisher encrypts
content under a data key and carries key access separately for authorized
recipients. Familiar analogies include:

- **Encrypted messaging:** Encrypt a message with a random symmetric key, then
  protect that key separately for each recipient. DCA similarly protects a
  content key separately for each issuer.
- **Managed envelope encryption:** Encrypt data with a data key, then protect
  that data key under separately controlled key-encryption material. DCA uses
  the same broad separation while assigning its actors different duties.

These are architectural analogies, not claims that those systems provide DCA's
protocol properties.

## Cryptographic primitives

DCA uses standard, widely deployed primitives exposed by WebCrypto. The
specifications and the reference tests cover its security-critical DCA-specific
composition, including BIND and the fixed ECDH transcript:

| Operation | Primitive | Notes |
|-----------|-----------|-------|
| Content encryption | AES-128-GCM | Fresh 16-octet content key per item and render. |
| Exact period key wrapping a content key | AES-128-GCM under a 16-octet exact period key | Random 96-bit nonce; cumulative per-key invocation bound. |
| Publisher-to-issuer ECDH envelope | P-256 ECDH raw 32-byte shared x-coordinate + AES-256-GCM | No KDF; BIND is GCM additional data. |
| Publisher-to-issuer RSA envelope | RSA-OAEP with SHA-256 | Recovered BIND and payload share one OAEP plaintext. |
| Optional issuer-to-client transport | Selected response-binding profile | Direct bytes or a separately identified client-bound construction; not inferred from publisher envelopes. |
| Resource signing | ES256 (ECDSA P-256) | Authenticates registered publisher claims; the browser profile compares the signed delivery origin with the observed `Origin`. |

DCA v1 fixes delivered `contentKey`, exact `periodKey` and positioned
`periodChainKey` values at 16 octets. This is a 128-bit classical symmetric-key
target. Fixed width avoids another interoperable state without a current
requirement and saves bytes in every wrapped key payload; it is not negotiated
per render or inferred from key length. A new strength target needs a new
suite/specification version. The retained `keyDerivationSecret` remains 32 octets;
the Root operation instead produces the 16-octet terminal/root state.
The publisher-to-issuer ECDH envelope key and the issuer-to-client HKDF
transport key both use AES-256-GCM; delivered client-bound handles use AES-128.

V1 is not post-quantum: its P-256/RSA envelopes and ES256 signatures would need
replacement. A later migration cannot revoke copied v1 artifacts or
retroactively protect their recorded envelopes. Chain-state disclosure still
reaches its bounded window prefix, while one exact leaf reaches one coordinate;
equal widths do not equate these capabilities. BIND and the derivation contexts
separate their roles, independently of length.

Base defines no period-key derivation primitive. Each extension document
inventories its own constructions.
