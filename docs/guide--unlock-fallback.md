# Unlock routing and fallback

Status: Informative Draft

This guide explains how a deployment can route unlock requests and preserve
availability when an issuer endpoint is unavailable. It does not add a
fallback flag, route list, or emergency mode to the DCA wire format.

The [core protocol](spec--core-protocol.md) and
[browser and HTTP binding](spec--browser-http-binding.md) define each unlock
exchange. The [threat model](spec--security-model.md) defines the security
boundary. Follow those documents where this guide disagrees.

The host-resolved routing model in this guide depends on the proposed
[removal of `unlockUrl` from the V1 wire](spec-proposal--remove-wire-unlock-url.md).
Until that proposal is adopted, this is deployment guidance rather than a V1
interoperability requirement.

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

The client advances only after a failure that its trusted route configuration
classifies as retryable. Every definitive authorization answer is terminal.

- A transport failure or issuer `5xx` response may advance the route.
- A successful response that supplies any key is terminal, including a
  partial grant. The client does not shop unresolved items to a more permissive
  issuer.
- A policy denial or not-delivered result is terminal. A client under the
  [`dca-v1-not-delivered-result` profile](spec--profiles.md#8-dca-v1-not-delivered-result-profile)
  reads non-delivery from an admitted `notDelivered` entry. Any such entry
  makes the issuer attempt terminal as a whole, even when independent
  operational errors appear in the same response.
- A `200` response containing only operational could-not-open results may
  advance only when the route explicitly classifies that complete outcome as
  retryable. A no-coordinate `200` is a terminal no-key outcome.
- The client fails visibly on a malformed, unsupported, or misconfigured answer.
- The client stops after the finite configured list and returns no key.
  It never loops.

Deployments may refine which operational failures are retryable, but they must
not reinterpret a denial, partial grant, or malformed response as permission
to seek a wider grant. A non-`200` response supplies no key material under the
HTTP binding.

## Availability choices at the issuer

Fallback does not require publishing plaintext or opening the site. An issuer
can choose a narrower or more reusable key according to the policy it can
safely evaluate:

| Choice | Availability benefit | Access reach and cost |
| --- | --- | --- |
| Direct `contentKey` | Limits one answer to one item in one render | Usually requires another issuer answer for another render |
| Exact `periodKey` | Lets the client reuse one grant across matching renders | Opens every retained item wrapped for that publisher, access group, and period |
| Client-bound delivery | Makes a captured response less reusable by another client | Prevents shared response caching and does not stop a reader controlling the client |
| Direct delivery | Allows identical authorized answers to be cached in a safe partition | Returns bearer key material that a recipient can share |

The issuer chooses the grant and delivery method. A client capability is an
offer, not an instruction to grant a particular key or use a particular
transport.

## Continuity and emergency policy

A reader-continuity policy needs issuer-verifiable positive entitlement state,
such as a locally verifiable snapshot. Identity alone selects an account or
cache partition; it does not prove entitlement.

A wider emergency audience is a separate operator decision. It must be
server-owned, explicitly activated, scoped to configured content or access
groups, expire at a stated time, and leave an audit trail. Request fields and
client-observed failures cannot activate it.

Direct content-key delivery can bound the cryptographic reach of an emergency
grant to one item and render. The operator must separately choose whether to
return a period key because it grants wider reusable access. That is a
deliberate choice. Neither shape
prevents an authorized reader from copying the key or plaintext.

No degraded policy relaxes resource-signature verification,
sealed-coordinate binding, or the rule that authorization finishes before
release. Browser deployments also retain signed and observed origin admission;
the HTTPS-only non-browser profile has no observed browser origin to compare.

## Health and activation

An automatic fallback decision should evaluate the dependency needed for a
real entitlement decision, not only whether the issuer process answers a
health URL. The operator should cache health results and coalesce concurrent
checks so unlock traffic cannot amplify probes.

The deployment must choose what an inconclusive health check means. A timeout
must not silently select open or closed operation. When an issuer cannot reach
the authority needed for its normal decision, it reports temporary
unavailability rather than fabricating a denial.

Primary and fallback describe deployment roles. An
endpoint may change role through server-owned configuration without changing
the publisher's sealed material.

## Response caching

Response caching is optional and never replaces authorization. Cache only a
final grant-bearing answer after request admission and policy evaluation. An
issuer may always return `Cache-Control: no-store`.

A reusable cache identity includes the issuer namespace, exact admitted
request, grant and delivery profiles, authorization partition, server-owned
decision epoch, and an expiry no later than every authority window that
permitted the answer. Closing an emergency window requires a purge or a new
epoch so an earlier answer cannot be replayed as a current decision.

Client-bound responses belong to one client capability and are not shared
answers. A direct response may be shared only inside its explicit
authorization partition. Cache expiry cannot recall keys already delivered;
those keys retain their defined cryptographic reach.

A cacheable browser-profile response still follows the HTTP binding's
exact-origin CORS rules and carries `Vary: Origin`. Authorization partitioning
does not replace the browser cache boundary.

## Shapes deliberately excluded

This guide does not recommend:

- publishing plaintext or silently opening the site;
- inferring authorization from a failed primary request;
- accepting route membership, order, or activation from page or request
  fields;
- trying another issuer for the same unresolved family after a denial,
  not-delivered result, or partial grant;
- adding route lists to the wire without a demonstrated interoperability need;
  or
- describing client-bound delivery as DRM.

The publisher decides which issuers receive sealed capabilities, the client
host decides where a trusted issuer integration runs, and the issuer decides
what the current reader may open.
