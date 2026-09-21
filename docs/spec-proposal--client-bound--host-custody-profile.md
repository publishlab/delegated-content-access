# Proposal: client-bound host custody profile

Status: Proposal
Target: [spec--profiles.md Section 7](spec--profiles.md#7-client-bound-custody-profiles); [spec--response-binding.md Section 6](spec--response-binding.md#6-client-bound-common-representation); [spec--browser-http-binding.md Section 4](spec--browser-http-binding.md#4-dca-browser-origin-profile)

This document has no protocol authority. If the editors accept it, they move a
selected, complete contract into the targets; if they decline it, they remove
this file.

## Introduction

This proposal adds an optional host-custody layer for client-bound delivery.
The publisher serves an unlock frame from a separate origin. That frame keeps
the non-extractable client private key and any client-side key cache. The render
page asks it to perform one narrowly defined content-opening action. This
changes who holds the key in the browser; it does not add a third
issuer-to-client algorithm. The two methods remain `ECDH-P256` and `RSA-OAEP`.

[Profiles Section 7](spec--profiles.md#7-client-bound-custody-profiles) defines
only those two methods today. It says nothing about a frame, a host origin,
messages, client-key enrollment, durable caching or how an issuer selects host
custody. [Response-binding Section 6](spec--response-binding.md#6-client-bound-common-representation)
defines `transport` and the cryptographic method, not where the browser keeps
the private key. This proposal must say how host custody combines with one of
those methods and whether the endpoint permits direct fallback.

## Motivation and boundary

Current client-bound delivery gives the browser non-extractable handles for
content keys and exact period keys. The DCA API therefore does not expose an
intermediate raw key string. However, code running in that browser context can
still use a reachable handle as an oracle. The issuer also cannot tell whether
a reader enrolled a browser-held key or an extractable key of their own.

Putting the handles on another origin stops render-page script from directly
reading that origin's storage or key handles. It can reduce what an injected
script can do directly, but the frame is not a DRM boundary. The script can
call whatever message operation the frame exposes. A reader can enroll their
own key unless the issuer has another trust signal. Code on the unlock origin,
a browser extension, or a reader who controls the browser can still use or
relay the access. The [threat model](spec--security-model.md) already accepts
those limits.

A frame deployment cannot enforce an issuer counter or quota. The issuer can count
requests or grants under its own identity and policy, but the browser can reuse
a cached key or copy plaintext without another request. It can also clear,
evict or partition browser storage. Locks between tabs cannot guarantee one
registration or one issuer request across crashes and different browsers.

The publisher must operate a second origin, embed its frame and mediate messages
to it. The issuer must also know why a request from that origin belongs to a
render served from another origin. The frame can reuse ECDH-P256 or RSA-OAEP,
but the deployment may still need new enrollment, admission or endpoint rules.

## Current browser-origin constraint

The issuer currently accepts a browser POST only when the verified
`resourceJWT.origin` exactly matches the browser's observed `Origin`. The signed
value names the render origin. It does not also mean a frame origin or any
subdomain owned by the same publisher. Therefore, the issuer will reject a DCA
POST sent by a separate unlock frame under the current rules.

This proposal therefore needs an authenticated rule that connects the render
origin, the frame origin observed by the issuer and the issuer's admission
check. It must not quietly change the meaning of the signed `origin`, weaken an
exact comparison to a subdomain check, or treat CORS as authentication. The
browser-binding spec defines only the DCA HTTPS unlock endpoint; it defines no
endpoint for registering, rotating or revoking client keys.

## Specification

## 1. Choosing the method and custody
Lands in: [spec--profiles.md Section 7](spec--profiles.md#7-client-bound-custody-profiles)

An issuer pairs host custody with exactly one existing client-bound method. It
does not replace `ECDH-P256` or `RSA-OAEP`. Still open: whether DCA gives this
layer a profile name or leaves it in deployment metadata, how the issuer
authenticates that choice, and whether the endpoint permits direct fallback.
The proposal adds no `transport` member or leaf encoding unless the final
design needs one.

## 2. Origins and frame
Lands in: [spec--profiles.md Section 7](spec--profiles.md#7-client-bound-custody-profiles); [spec--browser-http-binding.md Section 4](spec--browser-http-binding.md#4-dca-browser-origin-profile)

The publisher serves the render and unlock frame from different origins. The
final contract must specify their exact serialization, which render origins may
embed or message the frame, and how the issuer verifies the pair before it
checks policy or uses a private key. The publisher must also choose its CSP,
`frame-ancestors` allowlist and top-level-frame behavior. DCA does not define
those web-platform settings today.

Open question: what authenticated assertion or endpoint profile lets the issuer
connect the frame's observed Origin to the render, without changing what the
signed render origin means?

## 3. Messages
Lands in: undecided (a new host-custody contract, referenced by profiles)

The frame exposes one content-specific operation, not a general sign, decrypt,
derive or arbitrary-URL API. The proposal still needs to define the request,
the reply (for example, rendered plaintext or a content-key handle), replay
handling, allowed caller windows, origin and source checks, and abuse limits.
These choices interact: returning a key handle defeats the custody goal, while
returning plaintext still lets the render page copy that plaintext.

The frame must validate the sending window and origin, reply only to an exact
target origin, parse bounded messages, and define failures and replay handling.
No existing DCA grammar supplies those rules.

## 4. Custody and cache
Lands in: [spec--profiles.md Section 7](spec--profiles.md#7-client-bound-custody-profiles); [spec--response-binding.md Section 6](spec--response-binding.md#6-client-bound-common-representation)

The frame generates or loads the client private key, offers its public key, and
keeps any retained non-extractable exact-period-key handle or wrapped leaf. It
must not give the render origin the private key or a usable period-key handle.
Response binding still assigns `decrypt` usage to content-key handles and
`unwrapKey` usage to exact-period-key handles.

Still open: whether the client key lasts for one session or persists, and
whether the issuer associates it with an account or a separate client identity.
The frame must also choose how it stores, retains, evicts and rotates cached
keys and coordinates across tabs. None of those choices can promise that a
reload never fetches again, enrollment happens exactly once, or every use
consumes issuer quota.

## 5. Admission and failure
Lands in: [spec--response-binding.md Section 6](spec--response-binding.md#6-client-bound-common-representation); [spec--browser-http-binding.md Section 4](spec--browser-http-binding.md#4-dca-browser-origin-profile)

Under the current required client-bound profile, the issuer validates the
offered public key before it opens the publisher envelope. If the offer is
missing, malformed or unsupported, the issuer releases no direct key. The
profile does not register a host origin, manage client registration or
authenticate a frame.

The proposal must say whether the publisher or issuer enrolls a host, who
authenticates it, how the issuer connects a client key to an identity, when the
client may replace that key, and which observed origin the issuer admits. It
must also say whether a host failure stops the open or permits direct fallback.
Merely adding a frame does not fail closed; the endpoint must forbid direct
delivery.

## 6. Evidence
Lands in: undecided

`js/v1/extensions/client-bound-transport/` implements the two client-bound
cryptographic methods, and its tests cover those methods. The editors have not
checked host-custody evidence: nothing there covers browser-origin isolation,
frame-message checks, enrollment, accounting or the complete host-custody
flow.

Browser and integration tests must exercise the two-origin flow and rejected
messages. Reviewers must also inspect the issuer endpoint, framing policy,
storage behavior and any enrollment or accounting rules. Byte-level conformance
tests cannot prove those browser and operational properties. The final code
location and whether a CMS integration belongs in scope remain open.

## Results

Pending.
