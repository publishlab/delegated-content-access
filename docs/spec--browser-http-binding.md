# DCA HTTPS and browser endpoint binding

Status: Public Working Draft

## Abstract

This document binds DCA unlock requests and issuer responses to HTTPS. It
defines the authenticated confidential channel required for direct key
delivery and an optional browser profile that additionally binds a verified
publisher origin to the browser-observed HTTP `Origin` and emits exact CORS
permission. Non-browser clients use the HTTPS binding without implementing or
claiming browser Origin/CORS guarantees.

<a id="1-scope-and-requirements-language"></a>
## 1. Introduction

This document defines the HTTPS request/response exchange, endpoint
authentication assumptions, response association, HTTP caching boundary and,
when selected, browser Origin admission and CORS behavior.

It does not define DCA authorization, response key representations, caller
credentials, business policy or trusted-proxy products. The core,
response-binding and deployment boundaries define those concerns.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Endpoint-binding mechanisms

This document defines two composable endpoint-binding mechanisms. The profile
catalogue selects them as parts of complete DCA profiles:

- **DCA HTTPS JSON** is the issuer endpoint selected by the baseline profile.
  It supplies the authenticated confidential request/response channel required by
  [spec--response-binding.md](spec--response-binding.md).
- **DCA browser origin** adds browser-observed Origin admission and CORS. It is
  selected only for browser callers whose deployment claims the corresponding
  copy-site boundary.

A non-browser implementation MAY implement only DCA HTTPS JSON. It does not
send a synthetic browser `Origin`, does not process CORS, and does not claim
that the issuer verified the caller's page origin. Another selected request
binding must provide any caller-context property that deployment requires.

For a non-browser request, the issuer verifies `resourceJWT` and admits its
signed `origin` under the canonical serialization rules in Section 3.2. It MAY
apply a registration-level origin restriction, but it does not compare the
claim with an observed HTTP `Origin`. The admitted signed origin remains
publisher context and a reusable-capability cache partition. This path does
not provide or claim the browser profile's copied-page or calling-page-origin
boundary; caller authentication and issuer policy must decide whether the
non-browser principal may receive the presented capability.

## 3. DCA HTTPS JSON

### 3.1. Endpoint and channel

The client MUST NOT send a DCA request to an `unlockUrl` that is not an absolute
`https` URI, except under the development mode below. It MUST authenticate the
TLS server identity for that URI, reject certificate or host validation
failure, and use TLS according to current best practice in
[BCP 195](https://www.rfc-editor.org/info/bcp195).

The client MUST NOT follow an unlock redirect automatically. A redirect target
is another endpoint and requires fresh authenticated selection before a DCA
request is sent. The client MUST NOT forward caller credentials, the resource
assertion or sealed values to an unselected redirect target.

An explicitly selected development mode MAY use `http` only for `localhost`,
a subdomain of `localhost`, or the IPv4 loopback literal `127.0.0.1`. Such use
does not provide the production channel guarantee and MUST NOT carry production
credentials or production key material.

The selected browser-origin duties and their security boundary are stated in
[the DCA security model](spec--security-model.md#enforcement-boundary).

### 3.2. Canonical signed origin

The verified `resourceJWT.origin` value is admitted only when it is the ASCII
serialization `scheme://host[:port]` of one HTTP(S) origin under
[RFC 6454, Section 6.2](https://www.rfc-editor.org/rfc/rfc6454.html#section-6.2),
with these selected canonical rules:

- `scheme` is lowercase `https` in production; the development exception is
  limited as in Section 3.1;
- a domain host is lowercase, uses its IDNA A-label form and has no trailing
  dot;
- an IPv6 literal is bracketed and uses lowercase hexadecimal, no leading
  zeroes in a piece, and `::` for the leftmost longest run of at least two zero
  pieces; an IPv4-mapped address uses the same hexadecimal form rather than a
  dotted-decimal tail, and a zone identifier is forbidden;
- `port` is present only when non-default, is decimal 1 through 65535 and has no
  leading zero; and
- user information, path, query, fragment, trailing slash, whitespace and `|`
  are forbidden.

Registrable-domain, suffix, wildcard and subdomain matching MUST NOT replace
comparison of canonical origin values.

### 3.3. Request

The client sends one HTTP `POST` to the selected `unlockUrl`. The body is the
UTF-8 JSON serialization of exactly one DCA request object. The request media
type is `application/json`, and the client SHOULD advertise acceptance of that
response media type. The endpoint MUST reject a missing or incompatible
request `Content-Type` before JSON parsing and MUST apply a finite request-size
limit before unbounded parsing or buffering.

The HTTP exchange associates the response on that stream with the exact
request. The client MUST retain the parsed request's issuer, version and
presented-coordinate set until response admission completes. Connection reuse
or HTTP multiplexing MUST NOT permit a response to be applied to another
request or publisher delivery.

Caller authentication, cookies, bearer tokens, mTLS and anonymous access are
deployment choices. The endpoint MUST supply the resulting authenticated or
explicitly anonymous principal to core policy; transport success alone does
not authorize any coordinate.

### 3.4. Response

A successful DCA operation returns status `200` and an `application/json`
response body containing the response-bound issuer result. The client MUST
parse exactly one JSON value and MUST require a non-array object before applying
[spec--response-binding.md](spec--response-binding.md). A missing or
incompatible response `Content-Type` supplies no DCA result.

A non-`200` response supplies no key material, even if its body resembles a
successful result. It MAY contain a JSON error object for diagnostics. The
client MUST NOT apply `keys` from an error response.

A response containing keys is specific to its authorization and response
contract. The endpoint MUST send `Cache-Control: no-store` unless a selected
profile defines a cache key, audience, freshness interval and invalidation
rules that make reuse safe. This prohibition concerns intermediary and client
HTTP caching; it does not prohibit a private issuer-side computation cache that
re-runs request admission and returns a result permitted for the current call.

HTTPS authenticates the selected issuer endpoint and protects the exchange in
transit. It does not authenticate publisher claims, authorize the caller,
provide browser-origin isolation or make direct key bytes non-extractable.

## 4. DCA browser-origin profile

### 4.1. Applicability

This profile is selected when a browser sends the unlock request and the
deployment relies on the publisher page origin as a request-admission boundary.
It adds requirements to DCA HTTPS JSON; it does not replace TLS server
authentication or the response binding.

The browser supplies `Origin` according to the Fetch/CORS processing model.
That browser-provided value cannot be overridden by application script. A
reverse proxy or TLS terminator MUST strip client-supplied forwarding headers,
write its own observation, and pass exactly one value to the backend. The
backend MUST trust that value only on connections from configured proxy addresses; otherwise it
uses the direct `Origin` header. It MUST NOT accept a client-controlled
replacement or comma-concatenated proxy value.

### 4.2. Observed Origin admission

For the browser profile, the endpoint MUST obtain exactly one observed
`Origin` value. Missing, repeated, comma-joined, `null`, opaque or noncanonical
values cause the endpoint to refuse the request.

The endpoint admits the observed value under the canonical serialization rules
in Section 3.2. The endpoint independently admits the verified signed `origin`
under that section. Their comparison in Section 4.3 is byte-for-byte.

### 4.3. POST admission order

For a browser `POST`, the endpoint and issuer preserve this order:

1. Reduce the received header to exactly one canonical observed Origin or
   refuse without CORS permission.
2. Admit and parse the DCA request and version.
3. Select the publisher registration and verify `resourceJWT`, in the header
   admission order [spec--core-protocol.md](spec--core-protocol.md) Section 4.2
   fixes.
4. Admit the verified `origin` claim under Section 3.2 and require it to equal
   the observed Origin byte-for-byte.
5. Apply any registration-level origin restriction.
6. Only then consult an issuer response cache, run policy or perform
   publisher-envelope/private-key work.

The endpoint MAY authenticate the caller and capture bounded policy context
before signature and origin verification when its authentication mechanism
requires that ordering. It MUST NOT make an authorization decision, consult a
response cache or reach publisher-envelope/private-key work until the verified
origin comparison succeeds. Authentication failure releases no key material.

The readable publisher-to-client `resource.origin` value is not used. A
verified signature with a signed origin that differs from the observed origin
is refused even if both origins are registered to the publisher.

The endpoint cannot compare origins at preflight because a preflight contains
no `resourceJWT`. A successful preflight grants no DCA authority and predicts
neither caller authorization nor a successful POST.

### 4.4. CORS response

For an admitted browser origin, the endpoint emits:

```text
Access-Control-Allow-Origin: <exact observed origin>
Vary: Origin
```

It MUST NOT use `Access-Control-Allow-Origin: *`. If the selected caller-
authentication scheme uses browser credentials, it additionally emits:

```text
Access-Control-Allow-Credentials: true
```

and the browser request uses the corresponding credential mode. The presence
of credentials does not change issuer policy requirements.

Every browser-profile response, including a refusal without CORS permission,
MUST include or merge `Vary: Origin`. A POST response MUST NOT carry CORS
permission until the publisher assertion has been verified and its admitted
signed origin equals the observed origin. A later authorization denial MAY
carry permission for that exact origin. Exposing its body does not turn the
denial into a grant.

### 4.5. Preflight

An `OPTIONS` preflight carries no DCA request body and reaches no publisher
signature, caller policy, response cache or key operation. The endpoint admits
the canonical Origin against its preflight origin policy. On success it returns
status `204` with:

```text
Access-Control-Allow-Origin: <exact observed origin>
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: content-type
Vary: Origin
```

It also sends `Access-Control-Allow-Credentials: true` when the selected
credentialed browser mode requires it. A deployment that selects bearer tokens
for browser callers adds `authorization` to `Access-Control-Allow-Headers` and
adds nothing else. The base browser profile uses an uncredentialed
Fetch mode. Credentialed operation must select the Fetch credential mode and
the corresponding caller-authentication boundary explicitly. A refused or
malformed preflight returns no wildcard or reflected allow-origin header.

<a id="5-failures-and-privacy"></a>
## 5. Security considerations: failures and privacy

The endpoint refuses malformed methods, origins, media types, JSON and
unsupported versions before it returns any key material. An endpoint SHOULD
keep unauthenticated and unauthorized error bodies coarse enough not to expose
publisher registration, caller entitlement, opening-key existence or cache
state beyond the core failure model.

CORS controls which browser origins may expose a response to script. It does
not authenticate the caller, stop a non-browser client, authenticate the
issuer, or prevent same-origin script from using an admitted response. TLS,
caller authentication, verified publisher claims and policy remain distinct
boundaries.

Issuer requests reveal the selected issuer, publisher assertion, requested
coordinates and caller-network metadata to the issuer. Client-bound delivery
does not hide these values. Endpoint logs SHOULD minimize sealed values,
credentials, full assertions and key-bearing response bodies.

## 6. Dependencies

This specification depends on:

- [spec--core-protocol.md](spec--core-protocol.md) for request admission,
  publisher verification, policy ordering and failures; and
- [spec--response-binding.md](spec--response-binding.md) for response
  representation and client key admission.

## 7. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [BCP 195: Recommendations for Secure Use of TLS and DTLS](https://www.rfc-editor.org/info/bcp195)
- [RFC 6454: The Web Origin Concept](https://www.rfc-editor.org/rfc/rfc6454)
- [DCA core protocol](spec--core-protocol.md)
- [DCA issuer-response binding](spec--response-binding.md)
- [WHATWG Fetch Standard](https://fetch.spec.whatwg.org/)
- [DCA security model](spec--security-model.md)

## 8. Informative References

- [DCA data-format example](design--data-format--example.md)
