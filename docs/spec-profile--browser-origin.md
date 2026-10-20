# DCA browser-origin profile

Status: Public Working Draft

## Abstract

This optional profile binds a verified publisher origin to the browser-observed
HTTP `Origin` before an issuer authorizes a DCA unlock. It specifies proxy
handling, admission order, CORS responses and preflight behavior for browser
callers.

## 1. Introduction

`dca-profile-browser-origin` depends on `dca-profile-baseline` and the shared
[HTTPS JSON binding](spec--http-binding.md). The publisher, browser client,
issuer endpoint and any trusted proxy implement the duties below. Credentialed
browser mode adds no separate profile. The [profile catalogue](spec--profiles.md)
records the dependency and selection.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Browser-origin requirements

### 2.1. Applicability

This profile is selected when a browser sends the unlock request and the
deployment relies on the publisher page origin as a request-admission boundary.
It adds requirements to [DCA HTTPS JSON](spec--http-binding.md); it does not
replace TLS server authentication or the response binding.

The browser supplies `Origin` according to the Fetch/CORS processing model.
That browser-provided value cannot be overridden by application script. A
reverse proxy or TLS terminator MUST strip every client-supplied private
forwarding field that its issuer deployment could treat as trusted evidence
about the request's Origin, host or channel. It then operates in one configured
mode for that issuer route:

- In **pass-through mode**, it either forwards the received `Origin` field
  lines without combining, selecting, canonicalizing or replacing them, or
  first refuses input that fails the count or value requirements in Section
  2.2 and forwards the one unchanged valid `Origin` field.
- In **write mode**, it MUST first refuse raw `Origin` fields that fail the
  count or value requirements in Section 2.2. Only after that check may it
  write one private forwarding field containing its observation and forward
  the request. It MUST NOT turn repeated, comma-joined or malformed input into
  one admissible private value.

The backend trusts the private forwarding field only when the connection is
from a configured proxy that is operating in write mode. In every other case,
including a direct peer or a configured pass-through proxy, it uses the raw
`Origin` fields. A private field from another peer does not replace those
fields.

### 2.2. Observed Origin admission

For the browser profile, the endpoint MUST obtain exactly one observed
`Origin` value from the source that Section 2.1 selects. In write mode, the
trusted proxy determines it before writing its private observation, and the
backend MUST require exactly one such private field from that proxy. Missing,
repeated, comma-joined, `null`, opaque or values not canonical under
[HTTP binding Section 3.2](spec--http-binding.md#32-canonical-signed-origin)
cause refusal in either mode.

### 2.3. POST admission order

For a browser `POST`, the endpoint and issuer MUST preserve this order:

1. Obtain exactly one canonical observed Origin from the source selected in
   Section 2.1, or refuse without CORS permission.
2. Complete the admission that
   [core Section 6.2](spec--core-protocol.md#62-authentication-and-policy)
   requires through `resourceJWT` verification: request limits, carrier and
   version admission, `kid` resolution in the header order core Section 4.2
   fixes, and verification of the signed resource assertion.
3. Admit the verified `origin` claim under
   [HTTP binding Section 3.2](spec--http-binding.md#32-canonical-signed-origin)
   and require it to equal the observed Origin byte-for-byte.
4. Apply any registration-level origin restriction.
5. Only then consult an issuer response cache, run policy or perform
   publisher-envelope/private-key work.

The endpoint MAY authenticate the caller and capture bounded policy context
before `resourceJWT` verification and the origin comparison when its
authentication mechanism requires that ordering; that is no authorization
decision, and authentication failure releases no key material.

The readable publisher-to-client `resource.origin` value is not used. A
verified signature with a signed origin that differs from the observed origin
is refused even if both origins are registered to the publisher.

### 2.4. CORS response

After verified-origin admission in Section 2.3 succeeds, every response,
including `200` results, later `4xx` refusals and `5xx` failures, MUST carry:

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
signed origin equals the observed origin. Exposing a denial's body does not
turn it into a grant.

### 2.5. Preflight

An `OPTIONS` preflight carries no DCA request body or `resourceJWT`, so the
endpoint cannot compare origins there. It reaches no publisher signature,
caller policy, response cache or key operation, grants no DCA authority and
predicts neither caller authorization nor a successful POST. The endpoint
admits the canonical Origin against its preflight origin policy, a deployment
setting; syntax alone does not satisfy that policy. On success it returns
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
Fetch mode. A refused or malformed preflight returns no wildcard or reflected
allow-origin header.

### 2.6. Avoiding repeated denied unlocks

A browser integration SHOULD retain a short-lived private scheduling hint after
an explicit access denial, so an equivalent request in the same access context
does not reach the issuer on every page load. The issuer's integration chooses
the interval and supplies invalidation on sign-in, sign-out, account switch or
entitlement change. This profile fixes no duration or storage backend.

The integration MUST scope the hint to the trusted issuer route, publisher and
reader access context. It MUST NOT infer a broader denial from absent keys, a
partial grant, an unavailable report, an unreadable response or an operational
failure. A refusal status alone does not distinguish access denial from request
admission failure; an endpoint-specific contract may establish that distinction.
An admitted `notDelivered` entry with reason `denied` is an explicit family report,
but does not establish a denial on another resource. Broader suppression requires
an explicit decision from the trusted issuer integration.

Before acquiring keys, the browser continues to try capability it already holds.
A denial hint neither removes that capability nor revokes previously delivered
keys. Context changes invalidate pending denial recordings as well as retained
hints. These hints are application scheduling state, not cached HTTP responses:
actual unlock exchanges still follow the HTTP binding's `no-store` requirements.
Other client environments may supply their own scheduling policy.

Local reader lifecycle handling distinguishes clearing a denial decision from
retiring retained capabilities. The JavaScript reference offers awaited
`clearAccessDecisions()` and `clearReaderContext()` operations respectively.
The latter fences old asynchronous admissions, opening results and fallback as
well as clearing retained capability; it does not revoke copied keys or plaintext.
The host coordinates authentication, presentation, other client instances and
shared storage. See the reference [porting contract](../js/PORTING.md#browser-reader-context-lifecycle)
for structural cleanup and failure handling. These are local integration duties,
not additional wire requirements.

## 3. Security considerations: browser failures and privacy

CORS controls which browser origins may expose a response to script; it does
not authenticate the issuer, stop a non-browser client or prevent same-origin
script from using an admitted response. It does not authorize the caller;
caller authentication, verified publisher claims and policy remain distinct.

## 4. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [WHATWG Fetch Standard](https://fetch.spec.whatwg.org/)
- [DCA HTTP binding](spec--http-binding.md)
- [DCA core protocol](spec--core-protocol.md)
- [DCA security model](spec--security-model.md)
- [DCA profile catalogue](spec--profiles.md)
