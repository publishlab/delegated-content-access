# DCA HTTPS endpoint binding

Status: Public Working Draft

## Abstract

This document binds DCA unlock requests and issuer responses to HTTPS. It
defines the authenticated confidential channel, canonical signed origin
admission, JSON exchange and response association used by the baseline.
The optional [browser-origin profile](spec-profile--browser-origin.md) adds
observed Origin admission and CORS for selected browser callers.

<a id="1-scope-and-requirements-language"></a>
## 1. Introduction

This document defines the shared HTTPS request/response exchange, endpoint
authentication assumptions, response association and HTTP caching boundary.
The browser-origin profile defines observed Origin admission and CORS.
The [overview glossary](spec---overview.md#terms-across-the-specifications)
distinguishes this endpoint binding from related binding names.

It does not define DCA authorization, response key representations, caller
credentials, business policy or trusted-proxy products. The core,
response-binding and deployment boundaries define those concerns.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Endpoint-binding mechanisms

The profile catalogue selects the shared HTTPS JSON mechanism for the baseline
and may additionally select the browser-origin profile:

- **DCA HTTPS JSON** is the issuer endpoint selected by the baseline profile.
  It supplies the authenticated confidential request/response channel required by
  [spec--response-binding.md](spec--response-binding.md).
- **DCA browser origin** adds browser-observed Origin admission and CORS as
  [a separate profile](spec-profile--browser-origin.md). It is selected for
  browser callers whose deployment claims the corresponding copy-site boundary.

A non-browser implementation MAY implement only DCA HTTPS JSON. It sends no
synthetic browser `Origin` and processes no CORS. For its requests the issuer
verifies `resourceJWT` and admits the signed `origin` under Section 3.2 as
publisher context, but compares it with no observed HTTP `Origin`. This path
therefore provides and claims no copied-page or calling-page-origin boundary;
another selected request binding provides any caller-context property the
deployment requires. Caller authentication and issuer policy decide whether
the non-browser principal may receive the presented capability.

## 3. DCA HTTPS JSON

### 3.1. Endpoint and channel

The article identifies the issuer; the installed client integration supplies
its endpoint. Before sending a request, the client MUST select that endpoint
from trusted configuration for the captured publisher/deployment context and
`issuerName`. A carried `unlockUrl` MUST NOT influence selection, including
when local configuration is missing or fails. Ordinary setup supplies one
endpoint and response agreement with an authenticated or explicitly anonymous
caller mode. Multiple endpoints and endpoint discovery are optional host
capabilities, not publisher wire members.

The client MUST NOT send a DCA request to an endpoint that is not an absolute
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

The client sends one HTTP `POST` to the selected endpoint. The body is the
UTF-8 JSON serialization of exactly one DCA request object. The request media
type is `application/json`, and the client SHOULD advertise acceptance of that
response media type. The endpoint MUST reject a missing or incompatible
request `Content-Type` before JSON parsing and MUST apply a finite request-size
limit before unbounded parsing or buffering.
Compatible means the media type `application/json`, compared case-insensitively;
media-type parameters do not change compatibility. Repeated or malformed field
values are incompatible. Request and response bodies follow the UTF-8 and
byte-order-mark rules of
[data-format Section 2](spec--data-format.md#2-common-json-rules).

The HTTP exchange associates the response on that stream with the exact
request. Until response admission completes, the client MUST retain every
request fact that response binding
[Section 3](spec--response-binding.md#3-inputs-and-common-response-form)
requires for admission, including the selected issuer, the request version,
the presented set, and the publisher delivery and render. Connection reuse or
HTTP multiplexing MUST NOT permit a response to be applied to another
request or publisher delivery. The captured association MUST also retain the
selected endpoint, issuer alias, trusted publisher/deployment context and
credential or explicitly anonymous context used for the request. A later route
or credential refresh MUST NOT retarget pending work or apply its result to a
successor context; [core Section 2.2.1](spec--core-protocol.md#221-logical-client-contexts-and-pending-work)
governs its lifetime and effects.
This association binds the logical client and caller context, not immutable
credential bytes. Credential refresh within that same context follows host
policy and does not by itself create a successor context.

Caller authentication, cookies, bearer tokens, mTLS and anonymous access are
deployment choices. The endpoint MUST supply the resulting authenticated or
explicitly anonymous principal to core policy; transport success alone does
not authorize any coordinate.

### 3.4. Response

For every issuer result that
[spec--core-protocol.md](spec--core-protocol.md#7-core-issuer-result)
Section 7 defines, the endpoint returns a response with status `200` and an
`application/json` body containing the response-bound issuer result. This
includes a result that delivers no key, such as one that carries only
per-coordinate `errors`, or a `notDelivered` result that core Section 6.2
permits in place of a whole-request refusal. The client MUST parse exactly one
JSON value and MUST require a non-array object before applying
[spec--response-binding.md](spec--response-binding.md). A missing or
incompatible response `Content-Type` supplies no DCA result.

A non-`200` response supplies no DCA result and no key material, even if its
body resembles a successful result. It MAY contain a JSON error object for
diagnostics. The client MUST NOT apply `keys` from an error response.

The client MUST NOT trigger a conditional fallback from any `4xx` refusal,
including `408` and `429`. Trusted route configuration MAY classify a `5xx`
response as retryable. A redirect or another status supplies no DCA result and
does not by itself authorize fallback.

An endpoint MUST answer each whole-request failure with the status class
below; diagnostic error names and exact non-success status numbers remain
implementation choices. Rows that match a
[core Section 8](spec--core-protocol.md#8-failure-model) class use its name.

| Failure | HTTP status class |
| --- | --- |
| Malformed or unsupported request, including an unsupported version or algorithm or a mismatched request context; unauthenticated publisher assertion; unknown, ambiguous, inactive or retired signing `kid` | `4xx` |
| Request outside a finite admission limit or selected-profile finite output processing limit, missing or incompatible request media type, or a refused browser origin | `4xx` |
| An `issuerName` outside the endpoint's configured operating aliases | `4xx` |
| Complete authorization denial or definitive authentication failure | `4xx` |
| Unknown issuer opening key: the requested opening-key version is unavailable within the verified registration | `5xx` |
| No policy decision obtainable, or issuer configuration or internal failure | `5xx` |

An authoritative policy decision with no grants is a denial, not evidence of
operational unavailability. Missing opening-key material does not establish a
definitive reader denial. When key-lifecycle policy has retired an opening key,
the issuer reports `key_retired` per coordinate in a `200` result (core
Section 8), not a whole-request failure. A client uses the observable status
class, not diagnostic body names.

These status distinctions apply only when the client can observe the response.
In cross-origin browser use, a refusal without CORS permission, a network
failure and some redirect failures are indistinguishable to script;
[core Section 5.3](spec--core-protocol.md#53-multiple-issuers) treats such an
outcome as indeterminate. The browser-origin profile defines when CORS permission may be emitted.

Every unlock `POST` response is specific to its request and authorization
context, including a no-key result or refusal. The endpoint MUST send
`Cache-Control: no-store` unless a selected profile defines a cache key,
audience, freshness interval and invalidation rules that make reuse safe.
This prohibition concerns intermediary and client HTTP caching; it does not
prohibit a private issuer-side computation cache that re-runs request
admission and returns a result permitted for the current call.

## 4. Security considerations: failures and privacy

The endpoint refuses methods other than `POST`, except an `OPTIONS` preflight
when the browser-origin profile is selected, before returning key material.

An endpoint SHOULD keep unauthenticated and unauthorized error bodies coarse
enough not to expose publisher registration, caller entitlement, opening-key
existence or cache state beyond the core failure model.

HTTPS authenticates the selected issuer endpoint and protects the exchange in
transit. It does not authenticate publisher claims, authorize the caller or
make direct key bytes non-extractable. Caller authentication, verified publisher
claims and issuer policy remain distinct boundaries.

Issuer requests reveal the selected issuer, publisher assertion, requested
coordinates and caller-network metadata to the issuer. Client-bound delivery
does not hide these values. Endpoint logs SHOULD minimize sealed values,
credentials, full assertions and key-bearing response bodies.

## 5. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [BCP 195: Recommendations for Secure Use of TLS and DTLS](https://www.rfc-editor.org/info/bcp195)
- [RFC 6454: The Web Origin Concept](https://www.rfc-editor.org/rfc/rfc6454)
- [DCA core protocol](spec--core-protocol.md)
- [DCA issuer-response binding](spec--response-binding.md)
- [DCA data format](spec--data-format.md)
- [DCA security model](spec--security-model.md)

## 6. Informative References

- [DCA data-format example](design--data-format--example.md)
