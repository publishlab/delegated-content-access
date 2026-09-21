# DCA deployment patterns

Status: Informative Draft

## What this guide covers

A DCA client is a protocol role, not necessarily browser code. It reads a
publisher delivery, obtains allowed key capability from an issuer, and opens
protected items. That role can run in a browser, a publisher backend, a CDN or
edge worker, an independent paywall service, or an issuer-operated service.

This guide helps implementers choose a deployment; it does not define a new
protocol layer. The
[design overview](guide---overview.md) states the actor model; the
[threat model](spec--security-model.md) states security claims; and the
[focused specifications](spec---overview.md) state interoperable behavior.
This guide is non-normative and does not define a secure deployment profile by
itself. A deployment still applies every selected protocol profile and its own
authentication, custody, cache, and plaintext-delivery controls.

Moving a role does not silently change its contract. Browser-specific HTTP,
origin or client-custody rules apply only when that profile is selected. A
server that performs the client role still presents the signed publisher
context from the delivery. Reader or service authentication is a separate
deployment input outside base DCA; the issuer uses it only through the selected
authentication or deployment binding. The server does not pretend to be a
browser.

## One role, several hosts

```text
DCA client role
|-- Browser client
|   |-- direct keys
|   `-- client-bound keys
|-- Server client
|   |-- publisher backend
|   |-- CDN or edge worker
|   |-- paywall service
|   `-- issuer-operated service
`-- Hybrid
    |-- edge authorizes, browser opens
    |-- edge brokers browser-bound keys
    `-- server opens, transforms, then reseals for browser
```

The placement and the output are separate choices. A server can return
plaintext, return a transformed representation, or protect a new result for a
browser. An edge can merely gate a request, act as an issuer, broker another
issuer, or perform the complete client role. Calling all of these "edge DCA"
would hide the important differences.

## What stays the same across deployments

- The publisher can keep one encrypted render in a shared public cache.
- The issuer decides access from authenticated publisher context, reader or
  service identity, and issuer-held policy. Moving the client does not give an
  unsigned request authority.
- The DCA client opens only capability the issuer granted. A server client is
  not automatically an issuer.
- Plaintext and viewer-specific responses stay out of the shared public cache.
- An authorized reader can still copy plaintext. Server placement removes key
  delivery from one browser path; it does not make displayed content
  uncopyable.
- A stronger route must not silently fall back to a weaker route. Any direct,
  client-bound, plaintext or open-content fallback is an explicit deployment
  policy.
- Saved keys and plaintext remain usable within their original reach. Moving
  the client does not revoke material already delivered.

## Issuer integration and endpoint resolution

The publisher needs enough issuer information to seal content: a stable
`issuerName`, the current opening public key and `keyId`, and any selected
profiles. It should not need to maintain the issuer's live endpoint topology,
fallback order, health policy, or credentials in every render.

An issuer integration can register an endpoint route with the client host when
the publisher installs or loads that integration. In a browser deployment the
integration might be an issuer-supplied module or script. A server client can
use the same resolver boundary through local configuration or an installed
package. DCA does not require browser JavaScript as the registration mechanism.

The client intersects two sources before sending anything:

1. The publisher delivery says which issuers received sealed material and
   therefore have something they can open.
2. Trusted client-host configuration resolves each `issuerName` to the
   endpoint or ordered endpoint route that may receive a request.

This keeps endpoint changes and fallback policy out of each article without
requiring a publisher-operated synchronization service. The publisher still
chooses and trusts the installed integration. A third-party script running in
the publisher page has that page's script privileges, so deployments that do
not accept that trust use publisher-hosted code or server-side configuration.

The current V1 data format requires `unlockUrl` in each issuer entry, and the
core protocol requires it in a usable issuer block. A client host that follows
the routing above resolves `issuerName` through its own configuration and does
not act on `unlockUrl` as a trusted route. Removing the field from the
publisher delivery is an open proposal, not a selected change; see
[the remove-wire-`unlockUrl` proposal](spec-proposal--remove-wire-unlock-url.md).
Any portable discovery profile remains separate and must define its own trust
and disclosure rules. No page field may add an endpoint to a trusted route or
activate fallback.

## Browser client

The common DCA deployment runs the client in the reader's browser. This is the
shape covered by the
[browser-origin profile](spec--browser-http-binding.md#4-dca-browser-origin-profile),
not a requirement that every DCA client be a browser. The browser reads the
encrypted publisher delivery, asks an issuer for missing capability, and opens
the item locally.

```text
publisher/cache -- encrypted render --> browser
browser -- unlock request -----------> issuer
browser <-- granted keys -------------- issuer
browser -- opens item locally
```

### Direct keys

The issuer returns key bytes using the
[direct response representation](spec--response-binding.md#5-direct-representation).
This is the simplest route and works with direct content keys or reusable
period keys. Browser code can retain and use the returned key within its
granted reach. It is a reasonable deployment when that exposure is accepted.

### Client-bound keys

The issuer protects its answer for a client key, so copying the answer alone
does not make it usable under another client key. This changes response
delivery, not entitlement or the reach of the granted content or period key.
The [client-bound response specification](spec--response-binding.md#6-client-bound-common-representation)
defines that delivery. Browser custody choices separately determine whether
page script can extract a key, use a key handle, or call a plaintext operation.

Direct delivery is simpler to implement. Client-bound delivery limits reuse of a
copied response, but does not stop a reader-controlled browser from using its
capability or copying plaintext.

## Server client

A server can perform the same logical client work before serving an authorized
result to a reader. The server authenticates the reader under its own product
contract, obtains the DCA grant under an identity the issuer accepts, opens the
item, and then decides what to deliver.

```text
publisher/cache -- encrypted render --> server client
server client -- unlock request ------> issuer
server client <-- granted capability -- issuer
reader <-------- authorized result ---- server client
```

Unless a selected profile says otherwise, the issuer treats the server as one
DCA client identity. Toward the reader, it is a paywall or content service.
Reader sessions, plaintext delivery, watermarking and private response caches
after the item is opened are deployment behavior, not automatically DCA wire
behavior.

### Publisher backend

A publisher can add a server-client layer in front of its encrypted delivery.
The reader calls that layer instead of receiving DCA keys directly. The layer
reads the same encrypted render as other clients, asks the issuer, opens the
item, and returns the authorized result to the reader.

This extra layer can exercise one production pipeline or keep policy and
content services separated. It is usually redundant when the publisher
backend already holds the original plaintext and can serve it after an
equivalent access decision.

### CDN or edge worker

An edge worker can place the DCA client near the encrypted cache while keeping
plaintext and viewer-specific output in a private response path. This can
reduce reader latency, but it adds edge compute, key custody, authenticated
session handling and a new availability boundary. If the edge merely checks a
token and passes the encrypted render through, that component gates the
request; the DCA client that opens the item is elsewhere.

### Independent paywall service

A paywall or content service can authenticate the reader through an ordinary
server-side session, OAuth flow, signed token, or another web mechanism. The
reader does not ask the DCA issuer for keys. The paywall service acts as the
DCA client: it reads the encrypted publisher delivery, asks the issuer for
granted key capability, and opens the item. It can then deliver the full
article through a website, app, feed, or another authorized channel. It can
also return only the opened content or a transformed version for insertion
into an existing page.

From the reader's side, this is a conventional server-side paywall. DCA runs
behind it so the publisher's stored render can remain encrypted and
shared-cacheable, and so a separate issuer can still make the access decision.
The paywall service now handles content bytes and plaintext, rather than only
an access decision.

### Issuer-operated service

An issuer can operate the server client beside its entitlement service. The
roles are co-located but remain conceptually distinct: the issuer decides the
grant, then the client side opens the item and serves the result. This removes
one network hop but gives one service issuer keys, reader policy and content
plaintext. Deployments that need separation of custody should keep the roles
apart.

## Hybrid deployments

Hybrid deployments keep the browser as one participant while an edge or
backend performs a narrower job.

### Edge authorizes, browser opens

The edge can authenticate a reader and gate access to an unlock route or to an
encrypted delivery. The browser still receives keys and opens the item. If the
edge applies issuer policy and opens publisher-sealed issuer data, it is acting
as an issuer. If it only validates a service token before forwarding a request,
it remains a gate in front of the issuer.

This shape can reduce unwanted traffic and put session checks near the reader,
but it does not keep keys out of the browser.

### Edge brokers browser-bound keys

The edge can authenticate the session, forward the browser's requested
client-bound method and public key to a remote issuer, and relay the protected
answer. The browser remains the DCA client that opens the item; the edge does
not need plaintext or opening keys.

The existing client-bound response profile can protect the issuer's answer for
the browser key. It does not define edge-session authentication or how the edge
binds its forwarded request to that session. Those remain deployment-specific
unless a future named profile makes them interoperable. A new response binding
or fallback rule likewise needs its own named contract before independent
implementations can rely on it.

### Server opens, transforms, then reseals

A server client can open an item, create a viewer-specific result such as a
watermarked representation, and protect that result for a browser client. This
may be useful when the transformation itself is the product requirement.

Opening and resealing an unchanged item is usually extra work with no new
protection. A viewer-specific format, key derivation, client binding or failure
rule is not implied by base DCA; it needs a defined extension or a private
deployment contract.

## Choices you can make separately

Describe a deployment on each axis instead of naming only its host:

| Axis | Examples | Question to settle |
| --- | --- | --- |
| Client placement | Browser, publisher backend, edge, paywall service, issuer-operated service | Where are keys used and items opened? |
| Issuer placement | Remote service, edge-hosted service, co-located with the server client | Who holds issuer private keys and entitlement policy? |
| Reader result | Keys, plaintext, transformed plaintext, resealed representation | What reaches the reader, and what can be copied? |
| Grant reach | Direct content key, exact period capability, selected extension | How much content does one grant open? |
| Cache boundary | Public encrypted render, private key response, private plaintext response | Which values may be shared between readers? |
| Fallback | Refuse, alternate issuer, deliberately weaker route, open publisher variant | Who authorizes a change in protection? |

These choices prevent false equivalences. An edge-hosted issuer that returns keys
to a browser is not the same as an edge client that returns plaintext. A
server-side client using a remote issuer is not the same as giving the server
issuer private keys.

## Which patterns make sense

| Pattern | Assessment | Why |
| --- | --- | --- |
| Browser asks a remote issuer and opens locally | Current browser deployment shape | Direct and selected client-bound delivery already fit the client role. |
| Edge gates an encrypted render; browser opens | Useful deployment | Adds request gating without changing DCA bytes; browser key exposure remains. |
| Edge brokers a remote issuer's browser-bound answer | Useful with explicit trust and request handling | Existing methods may compose, but an edge-session binding is not implied. |
| Edge acts as issuer; browser opens | Possible role placement | Moves issuer keys and policy to the edge; it is not merely a cache optimization. |
| Server client asks a remote issuer and returns plaintext | Useful deployment | Keeps keys out of that browser route and moves plaintext handling and bandwidth to the server. |
| Issuer and server client run together | Possible, with both roles in one service | Saves a hop but concentrates policy, issuer keys and plaintext custody. |
| Server opens, transforms and reseals | Useful when the transformation matters | Viewer-specific output can justify the second protection step; interoperability may need an extension. |
| Publisher backend consumes its own encrypted render | Usually redundant | It is useful for pipeline separation, not because the publisher lacks the plaintext. |
| Server returns both raw keys and plaintext | Usually redundant and more exposed | The plaintext satisfies the immediate request while the keys add reusable capability. |
| Server opens an unchanged item and reseals it | Usually redundant | It adds work and a second key lifecycle without changing the content. |
| Personalized plaintext enters the public cache | Reject | Another reader could receive a response outside its authorization context. |
| Browser frame is treated as a secret display boundary | Reject | A reader or permitted page script can copy displayed plaintext. |
| Protocol failure silently selects open or direct delivery | Reject | Untrusted failure input must not authorize weaker protection. |

A publisher may make an explicit decision to provide an unencrypted fallback.
It is never the accidental result of an unlock failure.

## Caching and failures

The shared-cache benefit comes from keeping the publisher's encrypted render
identical across readers. Everything personalized sits after that boundary:

```text
public cache:   encrypted publisher render
private path:   grant, client-bound answer, plaintext or transformed result
reader state:   retained key capability and saved plaintext
```

A deployment can privately cache an authorized result when its cache key and
eviction rules preserve the complete authorization context. It must not infer
that a cached result is safe to share because the encrypted source was public.

On issuer or client failure, the safe default is no new capability and no new
plaintext. Only a retryable failure defined by the deployment's configured
route may advance to another endpoint. A policy denial, withholding result, or
partial grant is terminal and unresolved coordinates are not offered to a more
permissive issuer. Any weaker emergency route is activated by trusted
deployment policy, with its different exposure understood in advance.

## When new specification work is needed

No new DCA specification is needed merely because existing roles run in
another process or location. Write deployment guidance when all participants
operate under one deployment's documented contract for authentication, routing
and output handling, rather than making a cross-implementation DCA promise.

A pattern needs a proposal for an extension or profile when independent
implementations must agree on new:

- wire members, algorithms or key derivation;
- authenticated coordinates or response bindings;
- client, edge or service identity semantics;
- selection, downgrade or failure behavior;
- cache semantics visible across products; or
- claims that an implementation can advertise and test for conformance.

That boundary keeps product architectures open while making interoperable
promises precise.

## How this relates to familiar deployments

These patterns overlap with familiar industry shapes without making them DCA
protocol actors: server-side paywalls return authorized content, CDN gates use
signed requests or session tokens, license services return capability for
encrypted media, and watermarking services create viewer-specific output.
The publisher can ship one encrypted, shared-cacheable render while an
independent issuer makes the access decision for each request.
