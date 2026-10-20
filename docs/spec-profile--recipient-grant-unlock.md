# DCA recipient-grant unlock profile

Status: Public Working Draft

## Abstract

This specification defines the optional `dca-profile-recipient-grant-unlock`
and its bearer-credential endpoint binding. Configured issuers admit a common signed JWT for named items of one registered
publisher resource and return only current-render item content keys. Publisher,
issuer and delegated minting use the same claims. Opaque issuer references
remain an explicitly selected local form. Issuance endpoints and link carriage
are separate host operations.

## 1. Scope

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

This binding adds recipient authentication and authenticated grant scope to the
[baseline unlock](spec--core-protocol.md). It changes no DCA JSON request or
response member, publisher assertion, sealed-key envelope, BIND construction
or [response association](spec--response-binding.md).
[The profile catalogue](spec--profiles.md#8-dca-profile-recipient-grant-unlock-profile)
records its dependencies and composition. Grant issuance endpoints, upstream
initiator authentication, share UI, link syntax and storage are outside this
binding. The minting boundary below consumes authorized scope; it does not
define a CMS authentication protocol.

### 1.1. Profile selection and dependencies

This optional profile selects the recipient-grant unlock binding below for one
accountless recipient's issuer unlock attempt. It depends on the complete
`dca-profile-baseline` profile. A browser caller additionally selects
`dca-profile-browser-origin` and its exact-origin admission and CORS duties. HTML
extraction additionally composes `dca-profile-html-carrier`. Baseline claims
acquire no sharing duty without this selection.

Sections 2 to 6 of this document state every role's requirements and the
claim's evidence.

## 2. Grant and endpoint agreement

### 2.1 Common signed grant

A claimed implementation of this profile MUST support the common compact JWS
JWT form specified here. A grant MUST NOT contain a DCA key, private key,
initiator session credential or secret from which a DCA key derives. Its
protected header and payload are JSON objects. The token MUST use exactly
three nonempty, unpadded base64url segments. Signers MUST produce unique JSON member names. Verifiers MUST either reject
duplicate names or consistently use the lexically last member, as RFC 7519
permits. They MUST reject malformed UTF-8 or JSON and unsupported critical
headers.
This common form supports no critical header extensions. A verifier MUST reject
`crit` and `b64` members, including the unencoded-payload option. It MUST ignore
other additional noncritical header members, except the trust-establishing
members forbidden in Section 2.2. Ignored metadata neither supplies a key nor
changes the grant's scope or verification algorithm.
The signing input is the ASCII encoding of the original first segment, one
`.` octet and the original second segment, as specified by RFC 7515.

| Field | Presence | Meaning and admitted value |
| --- | --- | --- |
| Header `typ` | Required | Exactly `dca-share+jwt`, separating recipient grants from resource, login and mint-authorization tokens. |
| Header `alg` | Required | `ES256`, or explicitly configured optional `HS256`. |
| Header `kid` | Required | Identifier of one active entry within the trusted `publisher` namespace; the verifier selects the entry by (`publisher`, `kid`). |
| `publisher` | Required | Stable public publisher identifier, mapped by that entry to one trusted publisher registration. |
| `sub` | Required | Stable resource subject, exactly the verified `resourceId` under core Section 4.2, compared as code points without normalization and admitted by the [core Section 4.1](spec--core-protocol.md#41-producer-form) `resourceId` rule; no additional grant-specific grammar or length bound applies. |
| `contentNames` | Required | Array of 1 to 64 distinct values admitted by the data-format `contentName` grammar. |
| `iat` | Required | Nonnegative safe-integer JWT NumericDate, in seconds. |
| `exp` | Required | Nonnegative safe-integer NumericDate, strictly greater than `iat`. |
| `jti` | Required | Fresh grant identifier in the issuing authority's namespace. |
| `iss` | Optional | Issuing authority namespace; when present, exactly matches the namespace configured for the selected key. |
| `nbf` | Optional | Nonnegative safe-integer NumericDate, strictly less than `exp`; absent means no delayed-start restriction. |
| `aud` | Optional, subject to Section 2.2 | One logical application identifier or a nonempty array of distinct such identifiers. |

`kid`, `publisher`, supplied `iss` and each audience identifier MUST be
nonempty strings of at most 256 characters without U+0000 through U+001F.
`jti` MUST contain 22 to 256 ASCII letters, digits, `-` or `_`; minting MUST
generate at least 128 unpredictable bits for each grant identifier. The
authorized scope input does not set `jti`.
Identifier comparisons are case-sensitive with no normalization.
The compact token MUST contain at most 8192 ASCII characters. Every onboarded
verification key MUST have a finite positive safe-integer
`maxLifetimeSeconds`; the verifier MUST refuse `exp - iat` above that configured
bound.
The verifier MUST use a trusted clock and exact validity instants: `iat` MUST
NOT be in the future, a supplied `nbf` MUST be at or before the current time,
and the current time MUST be strictly before `exp`. No clock allowance applies.
Trusted configuration MAY impose shorter lifetimes or narrower
item scope. A verifier MUST refuse the whole grant if it names an item outside
the selected entry's permitted scope or exceeds that entry's maximum lifetime;
it MUST NOT trim signed claims to fit the entry. It MUST NOT widen the signed
claims.

Minting MUST consume an explicit upstream authorization decision approving
publisher, resource, item set and lifetime. The recipient bearer MUST NOT
serve as authorization to mint another grant. Editorial/promotional minting
uses publisher authorization. Reader gifting requires both authenticated
publisher sharing permission for that article/scope and issuer qualification
of the initiator; reading entitlement alone is insufficient. An issuer may
qualify other initiators or configure a delegate under its policy. The common
claims require neither recipient identity nor an accepting issuer's address.

### 2.2 Trust, algorithms and audience

Grant signers and verifiers claiming this profile MUST implement ES256,
ECDSA P-256 with SHA-256 and the 64-octet JWS signature encoding in RFC 7518.
They MAY implement HS256 using an explicitly configured HMAC-SHA-256 secret
of at least 256 bits. Every holder of that secret can mint; a MAC does not
identify which holder minted. Support does not enable an algorithm for every
key. The verifier MUST match `alg` to the selected entry's configured algorithm,
key type and recipient-unlock purpose before cryptographic verification.
It MUST NOT interpret a public verification key as an HMAC secret.

Trusted onboarding MUST bind each active grant verification key to its signing
purpose, issuing authority namespace, public publisher identity, parent
publisher registration and permitted scope/lifetime. `kid` selects only within
that trusted configuration. Unknown, ambiguous, inactive or retired entries
MUST be refused. A token-supplied key or key URL MUST NOT establish trust;
this common form does not admit `jwk`, `jku` or `x5u` headers. A supplied `iss`
MUST agree with the entry; absent `iss` uses the entry's configured authority.
Rotation MUST preserve that authority and publisher registration mapping.

`aud` identifies a logical relying application, not necessarily a physical
issuer or HTTP host. A verifier MUST recognize its configured logical audience
in a supplied string or array. It MUST reject a supplied audience when no
matching audience contract is configured. When one issuing authority issues
grants for multiple applications or relying parties, the deployment MUST
require and validate `aud` to prevent cross-application substitution, following
RFC 8725 Section 3.9. Omission is permitted only by a trusted audience contract
that does not require this separation. No common logical audience name or
issuer hostname is prescribed.

An issuer MAY apply a local revocation lookup keyed by configured issuing
authority, publisher and `jti`. A revoked grant MUST be refused. `jti` alone
supplies neither replay prevention nor a counter. Issuers accepting the same
token make independent policy and revocation decisions.

Harmless descriptive extra claims MAY be ignored. A form requiring additional
admission restrictions needs a separately selected, understood contract;
unknown claims cannot negotiate it. A receiver MUST refuse an unsupported
selected restrictive form. Extensions MUST NOT redefine or widen common scope.

### 2.3 Selected opaque local form

An issuer MAY retain an explicitly selected opaque reference form. That form
is issuer-issued, has at least 128 bits of unpredictable entropy and resolves
to issuer-held purpose `recipient-unlock`, the issuer's own audience, publisher
registration, stable `resourceId`, nonempty named item set, validity interval
and current local revocation state. Its grant store and encoding remain local.
A host MUST select signed JWT or opaque-reference admission through trusted
configuration before parsing or lookup. A failed JWT verification MUST NOT
fall back to reference lookup, ordinary login or anonymous policy. Supporting
this local form alone does not claim common signed-grant interoperability.

### 2.4 Endpoint selection

Before a recipient attempt, trusted client-host configuration MUST identify
one configured accepting issuer, its authenticated HTTPS endpoint, and
the registered publisher and resource to which the attempt applies. The host
MUST NOT infer that selection from the untrusted delivery, a link's target, or
the credential's presence or decoded claims. The selected endpoint uses the baseline
[HTTPS JSON binding](spec--http-binding.md#3-dca-https-json); a browser
caller also selects the [browser-origin profile](spec-profile--browser-origin.md#2-browser-origin-requirements).

## 3. Presentation

The client constructs the ordinary DCA request from the current signed render
for unresolved, named items. It MUST present only the selected issuer's
applicable `sealed.contentKeys` coordinates. It MUST omit
`sealed.periodKeys`, `sealed.chainKeys`, `periodGeometry` and
`requestedPeriodKeys`, including empty members. No grant selector
appears in the JSON body. When the render's block selects compact ECDH, the
client relays its top-level `envelope` member as
[compact ECDH Section 3](spec-profile--compact-ecdh.md#3-wire-selector-and-client-relay)
requires.

The host sends the unchanged grant as the sole bearer credential in one HTTP
`Authorization: Bearer <grant>` field on the selected issuer's unlock
`POST`. The credential MUST follow the `b64token` grammar in
[RFC 6750 Section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1):
one or more ASCII letters, digits, `-`, `.`, `_`, `~`, `+` or `/`, followed by
zero or more `=` characters. Its carriage is case-sensitive; clients
MUST NOT normalize or re-encode it. Producers use `Bearer`, one SP and the
credential. The host MUST NOT combine it with an ordinary login bearer in that
field or broadcast it to other issuers; the HTTPS binding's
[redirect rule](spec--http-binding.md#31-endpoint-and-channel)
applies. A browser Fetch caller MUST supply `Authorization` explicitly, use
`credentials: "omit"` to exclude ambient cookies and other ambient
credentials, and use `redirect: "error"`. Its preflight MUST request
`authorization` and `content-type`; the endpoint applies the exact-Origin
[preflight rule](spec-profile--browser-origin.md#25-preflight).

The recipient host decides how to obtain and retain the grant under its
credential-handling policy. This specification selects no URL query or
fragment syntax. A host that uses a link MUST account for history, referrers,
previews, logs and redirects before exposing the bearer through that link.
URL cleanup cannot undo its initial exposure.
Retention MUST remain partitioned to the selected host credential context and
MUST NOT outlive the grant. This binding defines no issuer session exchange.
A direct-bearer host MUST set a finite local retention deadline at or before
the signed expiry before retaining a captured grant; issuer validation remains
the authority for admission.

## 4. Issuer admission and result

An endpoint configured to admit a recipient-grant attempt MUST reject, for
that attempt, a missing, duplicate, combined, malformed or non-Bearer
`Authorization` field, and a field with authentication parameters or
whitespace inside the credential; it admits the scheme case-insensitively with
one or more SP separators. Trusted endpoint context MUST select this binding
before credential lookup; trying different credential stores MUST NOT select
the request binding. A dedicated endpoint is the ordinary setup; an explicitly
selected shared endpoint is also permitted. An ordinary attempt without a
selected grant remains governed by its separately selected
caller-authentication contract. The endpoint may reject header syntax before
DCA parsing, but it MUST NOT look up or use a grant for policy or opening work
until it has admitted the DCA request, selected one publisher registration,
verified `resourceJWT` under that registration, and completed the selected
request binding's checks. The host MUST NOT treat the unsigned `issuerName` or
diagnostic `resource` copy as grant audience or authenticated
publisher/resource proof.

For the selected signed form, the issuer MUST verify the original compact
signature or MAC under trusted grant-key configuration, validate Section 2's
claims, time, audience, revocation and configured scope, and match the resulting
publisher registration and `sub` to the verified current resource assertion.
All grant time-validity checks for one attempt MUST use one captured trusted admission
instant; this introduces no clock allowance for a future `iat` or `nbf`.
For the explicitly selected opaque form, it MUST resolve the record only under
its trusted issuer identity and check purpose, own audience, validity,
revocation, publisher registration and resource. An invalid credential MUST
refuse the whole request before opening-key lookup, with no grant-derived
policy input, anonymous principal or ordinary-login fallback. The public body
of that refusal SHOULD avoid revealing which signature, trust, scope, time or
revocation check failed.

The issuer MUST refuse a selected grant request containing `sealed.periodKeys`,
`sealed.chainKeys`, `periodGeometry` or `requestedPeriodKeys`, including empty
members. For an admitted request that presents only item
content-key coordinates, it MUST reduce the grant to scoped policy input and
intersect its named item set with the request's admitted presented
coordinates, the publisher's entrusted material and the issuer's current
authorization decision. A grant at one issuer opens only named items whose
current render supplies an item content-key envelope to that issuer; the
credential does not create a missing publication route. A valid grant does
not override a current policy denial. The only key results
this selection permits are item `contentKeys` for the current render;
`periodKeys` and `chainKeys` are forbidden. The issuer MAY use a separately
selected client-bound response method to protect an item content key without
changing that key's kind or reach.

The grant may cover a later render of the same registered publisher and
stable `resourceId` while it is live. A changed item retaining a granted
`contentName` remains in scope; a new name does not. Each unlock requires a
fresh issuer decision.

## 5. Client admission and independent attempts

The client MUST apply ordinary request/response association, then refuse a
grant-result response containing a period-key or chain-key result or chain
geometry. It MUST NOT retain or use such a broader capability. It may open
only an associated current-render item content key for a selected item.

An absent grant does not select this profile for an attempt. After a failed
selected grant attempt, ordinary login or another issuer MAY be tried only
as a separate attempt under trusted host selection. The client MUST NOT
replay the failed bearer to another issuer or treat refusal as permission to
relax authentication.

## 6. Conformance boundary

A claim of `dca-profile-recipient-grant-unlock` MUST demonstrate authorized ES256
minting and complete signed recipient presentation through item opening,
including a later render with a changed item under the same granted name.
It MUST cover unknown/retired keys, wrong purpose/algorithm, tampering,
conflicting `iss`, audience mismatch and required-audience omission,
publisher/resource/name mismatch, invalid time/size bounds, expired/revoked
grants, unpresented coordinates and overbroad key results. Every claimed
optional algorithm or local form MUST have its own positive/refusal
evidence. Support, deployment enablement, one operation's presentation and
issuer admission are distinct claim facts.

The claim does not imply an interoperable issuance endpoint, share UI, link
syntax, opaque-reference encoding or storage, use-count rule, atomic retry
accounting, or immediate revocation protocol. An issuer may enforce local
count limits, but any response reuse MUST preserve its selected local
accounting and the current-call authorization rule.

## 7. Security considerations

The grant is a bearer credential: disclosure permits presentation until
expiry or revocation, subject to current issuer policy. TLS endpoint
authentication, signed publisher claims, selected browser-origin admission,
grant audience validation, scope intersection, BIND and response association
protect different boundaries; none substitutes for another. A client-bound
response protects a delivered item key for one client but does not make the
bearer itself client-bound.

## 8. Normative References

- [BCP 14](https://www.rfc-editor.org/info/bcp14)
- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/info/rfc7515)
- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/info/rfc7518)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/info/rfc7519)
- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/info/rfc8725)
- [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/info/rfc6750)
- [DCA core protocol](spec--core-protocol.md)
- [DCA data format](spec--data-format.md)
- [DCA HTTP binding](spec--http-binding.md)
- [DCA browser-origin profile](spec-profile--browser-origin.md)
- [DCA response binding](spec--response-binding.md)
- [DCA profiles](spec--profiles.md)
- [DCA security model](spec--security-model.md)
