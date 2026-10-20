# Unlock routing and fallback

Status: Informative Draft

This guide explains how a deployment can route unlock requests and preserve
availability when an issuer endpoint is unavailable. It does not add a
fallback flag, route list, or emergency mode to the DCA wire format.

The [core protocol](spec--core-protocol.md) and
[HTTPS endpoint binding](spec--http-binding.md) define each unlock
exchange. The [security model](spec--security-model.md) defines the security
boundary. Follow those documents where this guide disagrees.

Articles name their issuers and carry sealed material, without an unlock URL.
Installed client integrations or explicit trusted configuration supply endpoints.
Clients ignore any URL left in older deliveries; they never use it as a fallback.

## Why routing does not belong in publisher data

The publisher needs enough information to seal keys for an issuer: a stable
issuer name, an opening public key, a key identifier, and the selected
profiles. It does not need to know the issuer's current endpoint topology for
every article.

The client host is better placed to resolve the issuer name to a trusted
endpoint or ordered route. The host knows which integration is installed,
which credentials it may send, which endpoints it trusts, and which failures
may advance to another endpoint. An issuer can then rotate or add endpoints
without requiring the publisher to render every cached article again.

An issuer may provide a browser module, script, server package, or
configuration adapter that registers its route when the publisher installs
the integration. DCA defines the boundary between publisher material and
trusted route configuration, not the packaging mechanism.

An issuer-provided browser script runs with the page privileges the publisher
grants it. Route registration is not automatically trustworthy merely because
the issuer supplied the script. A publisher that does not accept that trust
can host the integration itself, isolate it, or resolve routes on a server.

Keeping routes outside publisher-delivered page data also prevents a page
field from choosing where the client sends signed resource assertions, sealed
keys, request coordinates, credentials, and traffic timing.

## An issuer must be present on both sides

A configured route alone grants nothing. The publisher must also have supplied
applicable sealed material for the same issuer.

```text
publisher supplied sealed material for issuerName
                    AND
client host configured a trusted route for issuerName
                    |
                    v
             issuer is eligible
```

If either side is missing, the client sends no request. Publisher data cannot
add an endpoint, reorder a route, activate fallback, or widen issuer policy.
Local configuration cannot make an issuer eligible for content the publisher
did not seal for it.

## Who controls what

- The publisher chooses which named issuers receive sealed material and which
  content items and access groups exist.
- The client host chooses trusted endpoint membership, order, credentials,
  retry classification, breaker behavior, and exhaustion.
- Each issuer verifies the publisher assertion, performs the applicable
  browser or server request admission, authenticates the reader when required,
  and decides what keys to return.
- The operator controls any degraded or emergency issuer policy. A request can
  ask the issuer to evaluate its current policy, but it cannot activate or
  widen that policy.

Every path completes authentication and authorization before releasing key
material or plaintext. A failed primary request is evidence only that the
client may try another configured endpoint. It is never evidence that the
next issuer should grant access.

## Redundancy and independent custody

Several endpoints can represent one issuer and keyset. They provide deployment
redundancy when they share the opening keys and policy state required to answer
as that issuer. The publisher seals once for that named issuer.

A second named issuer provides independent custody only when the publisher has
also sealed the requested material for its separate keyset. Its operation,
storage, and control plane must be independent if the deployment expects it to
survive failure of the first issuer.

Several endpoints for the same issuer can appear in one trusted ordered route.
A deployment that may try a second named issuer needs an outer attempt plan:
for each attempt the client selects that issuer's matching publisher-supplied
block and resolves that issuer's own route. It never sends one issuer's request
block to another issuer merely because that issuer is next in the plan. An
issuer for which the publisher supplied no applicable sealed material is
skipped without a network request.

## When the client may advance

The client advances along a fallback route only after an outcome that its
trusted route configuration classifies as retryable. Every definitive
authorization answer is terminal for that route.

- Fetch TypeError, opaqueredirect and post-send deadline failures are
  indeterminate outcomes ([core Section 5.3](spec--core-protocol.md#53-multiple-issuers);
  the [HTTPS endpoint binding](spec--http-binding.md#34-response) says why
  script cannot tell a refusal from a network failure); the JS reference
  transport tags them `indeterminate_transport`. They do not permit a
  conditional backup, though an independent route remains permitted.
  An unexpected untagged programming exception propagates and ends the walk.
- A locally attributable pre-send transport failure or issuer `5xx` response
  may advance the route when trusted configuration classifies it as retryable.
  An issuer `4xx` refusal,
  including a whole-request policy denial, is terminal for conditional
  fallback. An HTTP `429` rate-limit response is therefore terminal too.
  Temporary unavailability reported as a `5xx` can advance only when trusted
  configuration classifies that response as retryable.
- Apply admitted keys and recompute unresolved items first. Success for an
  unrelated identity does not cancel an explicitly eligible family retry.
  An item already opened by a returned or retained key needs no retry. Trusted
  route policy can still stop the whole attempt after a partial grant.
- A policy denial is terminal. An admitted
  [`notDelivered`](spec-profile--period-keys.md#56-family-reports-notdelivered)
  entry with reason `denied` ends the attempt for that family and never
  advances the route, whatever else the response carries.
- An admitted `notDelivered` entry with reason `unavailable` reports
  availability, not a denial. The route may explicitly classify it as
  retryable for that family if it remains useful to an unresolved item after
  applying the result. It qualifies neither a silent item content-key
  alternative nor a sibling family. Without that trusted classification it
  is terminal. The next issuer applies its own policy.
- Core source-coordinate opening errors have no default retry meaning. Only
  an applicable selected profile may give the actual reported source coordinate
  local retry meaning; it cannot qualify the whole family. A no-coordinate `200` without a `notDelivered` entry is a
  terminal no-key outcome, and its silence says nothing about why.
- The client fails visibly on a malformed, unsupported, or misconfigured answer.
- The client stops after the finite configured list and preserves any admitted
  capability it already received.
  It never loops.

These rules govern a conditional fallback: a backup issuer that the client
tries only because of the earlier outcome. Listing an issuer as a backup does
not by itself authorize an attempt to it. Trusted client configuration permits
an independent attempt whatever the earlier issuer answers, for example when
the host is configured to ask both issuer A and issuer B for an item. The
publisher must have supplied B's own sealed material, and B applies its own
policy. A's denial, partial grant or `notDelivered` entry neither triggers nor
cancels the attempt to B, as the
[core protocol](spec--core-protocol.md#53-multiple-issuers) requires.

Build the next request from eligible issuer-specific `contentName` or
`accessGroup` identities, not simply from every item still unopened. A retryable
`unavailable` report for
`standard` may carry B's own `standard` period supply, but cannot carry A's
denied `premium` family or silently add an item content-key alternative that
the prior request omitted. That alternative needs its own retryable outcome
or an independent attempt. Skip B when no eligible identity remains.

Deployments may refine which operational failures are retryable, but they must
not reinterpret a denial, silence, unrelated partial grant, or malformed response as permission
to seek a wider grant. A non-`200` response supplies no key material under the
HTTP binding.

## Availability choices at the issuer

Fallback does not require publishing plaintext or opening the site. An issuer
can choose a narrower or more reusable key according to the policy it can
safely evaluate:

| Choice | Availability benefit | Access reach and cost |
| --- | --- | --- |
| Item `contentKey` | Limits one answer to one item in one render | Usually requires another issuer answer for another render |
| `periodKey` | Lets the client reuse one grant across matching renders | Opens every retained item wrapped for that publisher, access group, and period |
| Client-bound delivery | Makes a captured response less reusable by another client | Prevents shared response caching and does not stop a reader controlling the client |
| Direct delivery | Allows identical authorized answers to be cached in a safe partition | Returns bearer key material that a recipient can share |

The issuer chooses the grant and delivery method. A client capability is an
offer, not an instruction to grant a particular key or use a particular
transport.

## Continuity and emergency policy

A reader-continuity policy needs issuer-verifiable positive entitlement state,
such as a locally verifiable snapshot. Identity alone selects an account or
cache partition; it does not prove entitlement.

Keep a wider emergency audience server-owned: activate it explicitly, scope it
to configured content or access groups, give it an end time and an audit
trail. Request fields and client-observed failures never activate it, because
request presence grants nothing
([core Section 6.1](spec--core-protocol.md#61-presented-coordinates)).

Item content-key delivery can bound the cryptographic reach of an emergency
grant to one item and render. The operator must separately choose whether to
return a period key because it grants wider reusable access. That is a
deliberate choice. Neither shape
prevents an authorized reader from copying the key or plaintext.

No degraded policy relaxes resource-signature verification,
sealed-coordinate binding, or the rule that authorization finishes before
release. Browser deployments also retain signed and observed origin admission;
a route without the browser-origin profile has no observed browser origin to compare.

## Health and activation

An automatic fallback decision should evaluate the dependency needed for a
real entitlement decision, not only whether the issuer process answers a
health URL. The operator should cache health results and coalesce concurrent
checks so unlock traffic cannot amplify probes.

Decide in advance what an inconclusive health check means, so a timeout never
silently selects open or closed operation. An issuer that cannot reach the
authority it needs has no policy decision and answers with temporary
unavailability ([core Section 6.2](spec--core-protocol.md#62-authentication-and-policy)).

Primary and fallback describe deployment roles. An
endpoint may change role through server-owned configuration without changing
the publisher's sealed material.

## Response caching

The HTTPS endpoint binding defaults to `Cache-Control: no-store`
([Section 3.4](spec--http-binding.md#34-response)); reuse needs a
selected profile that defines its cache key, audience, freshness and
invalidation, and a client-bound response is never a shared answer
([response binding Section 9](spec--response-binding.md#9-replay-caching-and-composition)).
A reused browser-profile response still follows exact-origin CORS and carries
`Vary: Origin` ([browser-origin Section 2.4](spec-profile--browser-origin.md#24-cors-response)).
A stored refusal, no-key result or key result is usable only while the current
policy decision would produce it.

A reusable cache identity includes the issuer namespace, exact admitted
request, grant and delivery profiles, authorization partition, server-owned
decision epoch, and an expiry no later than every authority window that
permitted the answer. Closing an emergency window requires a purge or a new
epoch so an earlier answer cannot be replayed as a current decision.

Cache expiry cannot recall keys already delivered.

## Shapes deliberately excluded

This guide does not recommend:

- publishing plaintext or silently opening the site;
- inferring authorization from a failed primary request;
- accepting route membership, order, or activation from page or request
  fields;
- advancing a fallback route to another issuer for the same unresolved family
  because of a denial, a `denied` entry, or success for another identity;
- adding route lists to the wire without a demonstrated interoperability need;
  or
- describing client-bound delivery as DRM.

The publisher decides which issuers receive sealed capabilities, the client
host decides where a trusted issuer integration runs, and the issuer decides
what the current reader may open.
