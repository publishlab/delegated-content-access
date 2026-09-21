# Proposal: remove `unlockUrl` from the V1 wire

Status: Proposal
Target: [spec--data-format.md Section 4.2](spec--data-format.md#42-issuerdata);
[spec--core-protocol.md Section 9](spec--core-protocol.md#9-delegation-completeness);
[spec--browser-http-binding.md Section 3.1](spec--browser-http-binding.md#31-endpoint-and-channel)

This document has no protocol authority. If the editors accept it, they move
its requirements into the targets and remove this proposal file.

## Introduction

The working V1 format places an `unlockUrl` in every publisher delivery. At the
same time, the client host owns endpoint selection, route order, retry policy,
health, and fallback. One page-carried URL cannot describe that deployment
state and should not become routing authority merely because it is on the
wire.

This proposal removes `issuerData[issuerName].unlockUrl` before V1 settles.
The client host resolves the stable `issuerName` through trusted integration
configuration and intersects that configuration with the issuer material the
publisher actually supplied.

The deployment guide describes the human deployment shape in
[Issuer integration and endpoint resolution](guide--deployment-patterns.md#issuer-integration-and-endpoint-resolution).
The consequences for ordered fallback are described in
[DCA unlock fallback](guide--unlock-fallback.md).

## Motivation

The publisher must know enough about an issuer to seal content for it: the
stable issuer name, opening public key, `keyId`, and selected profiles. The
publisher does not need the issuer's live endpoint topology in every article.

Keeping runtime routes outside the render provides four useful properties:

- an issuer can change or add endpoints without forcing the publisher to
  rerender cached content;
- a client can apply endpoint allowlists, credentials, health, breakers, and
  retry rules before disclosing a request;
- fallback membership and order cannot be injected through page data; and
- the same publisher delivery works for browser, server, edge, and paywall
  clients whose endpoints or credentials differ.

An issuer may supply a browser module, script, server package, or configuration
adapter that registers its route when the publisher installs the integration.
DCA defines the resolver boundary, not that packaging mechanism. This avoids
requiring a publisher-operated endpoint synchronization service with its own
storage, authentication, and failure modes.

## Proposed V1 change

### 1. Publisher delivery

Lands in: [spec--data-format.md Section 4.2](spec--data-format.md#42-issuerdata)

Each `issuerData[issuerName]` block contains `keyId`, `sealed`, and any members
selected by an extension. It does not contain `unlockUrl`.

The publisher still chooses which issuers receive sealed material. Removing
the URL does not let locally configured issuers open content that the publisher
did not seal for them.

### 2. Client-host resolution

Lands in: [spec--browser-http-binding.md Section 3.1](spec--browser-http-binding.md#31-endpoint-and-channel)

Before sending a request, the client host resolves the selected `issuerName`
through trusted deployment configuration. Resolution returns one endpoint or
an ordered endpoint route plus the transport credentials and policy needed to
use it. A browser script is one possible integration mechanism, not a protocol
requirement.

The client sends nothing when either side of this intersection is absent:

```text
publisher supplied sealed material for issuerName
                    AND
client host configured a trusted route for issuerName
                    |
                    v
             issuer is eligible
```

The publisher delivery cannot add an endpoint, reorder a route, activate
fallback, or change which failures advance the route. The client host does not
infer those decisions from `issuerName`, `keyId`, or sealed material.

### 3. Delegation completeness

Lands in: [spec--core-protocol.md Section 9](spec--core-protocol.md#9-delegation-completeness)

A usable issuer block no longer depends on `unlockUrl`. Publisher-side
delegation completeness continues to require suitable sealed material for at
least one issuer-mediated opening route. Whether a particular client host has
a configured endpoint for that issuer is deployment readiness, not a field the
publisher proves inside each render.

### 4. Endpoint and fallback behavior

The selected HTTPS endpoint profile continues to require an absolute HTTPS
endpoint, authenticated TLS, redirect refusal, request admission, and the
existing response rules. This proposal changes where the client obtains the
endpoint, not how the exchange behaves.

Route advancement remains deployment-owned. A denial, withholding result, or
partial grant is terminal. Only a failure that the trusted route configuration
explicitly classifies as retryable may advance to another endpoint.

## Security considerations

Removing `unlockUrl` prevents mutable publisher markup from choosing where a
client discloses the signed resource assertion, sealed values, request
coordinates, credentials, and traffic timing. It does not make endpoint
configuration automatically trustworthy. A compromised integration or local
configuration can still redirect those values, so clients authenticate the
configured endpoint and protect their configuration boundary.

An issuer-supplied script executes with the privileges the publisher page gives
it. Publishers that do not accept that trust use publisher-hosted code,
isolated execution, or server-side configuration. The protocol does not hide
that deployment choice.

Server clients must also constrain resolved endpoints to prevent untrusted
input from becoming an SSRF target. A page value never becomes a URL merely
because no local route exists.

Portable endpoint discovery is outside this proposal. Any later discovery
profile must define its trust anchor, caching, refresh, disclosure, credential,
and failure behavior explicitly.

## Reconciliation and evidence

This is V1 draft reconciliation, not a V2 compatibility feature. Adoption
requires the coordinated changes below:

- the data-format and endpoint-binding specifications;
- core delegation-completeness wording;
- publisher configuration and rendered `issuerData`;
- client parsing, endpoint resolution, and response association;
- examples, fixtures, vectors, conformance bridges, and cross-runtime tests;
  and
- the browser and server demonstrations.

Evidence must show unchanged publisher delivery across endpoint rotation, no
request when the host lacks a trusted route, no request to a configured issuer
for which the publisher supplied no applicable material, and no route advance
after a definitive denial, withholding result, or partial grant.
