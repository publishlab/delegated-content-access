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
[security model](spec--security-model.md) states security claims; and the
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

## Hosting the reference issuer endpoint

Compose `createIssuerCore` behind the host's selected caller binding. Check the
request `Content-Type` and apply finite body limits before parsing JSON. Admit
the raw body with `processor.admit`; map a refusal with `endpoint.refusal`.
Read the admitted request's header `kid` only as an untrusted lookup hint to
select the publisher registration, then call `endpoint.handleRequest` with that
same admitted request and registration. The endpoint verifies the assertion
under that registration; the lookup hint does not authenticate it.
`endpoint.handleDocument` suits a host that already holds its one registration;
it does not supply the host's HTTP checks. Write key-bearing responses with
`Cache-Control: no-store`, unless a selected profile defines the alternative
cache agreement required by the
[HTTP binding](spec--http-binding.md#3-dca-https-json).

Keep each non-empty signing `kid` active in at most one registration, as
[core Section 4.2](spec--core-protocol.md#42-verification-and-registration) requires.
Caller authentication, captured policy context and opening-key registration
remain host duties; this entry is not a complete HTTP adapter.

## Describing support and compatibility

When describing an implementation, start with the DCA version and the roles it
implements: publisher, issuer, client, or a combination. Then name the optional
profiles it supports. Check each claim against the applicable duties, their
dependencies and the evidence those specifications require. A feature being
present in the code, or one test passing, does not establish the whole claim.
The [profile specification](spec--profiles.md#12-conformance-claims) defines
what a conformance claim must include.

When describing a deployment, also say which supported profiles are enabled
and what its publications require from clients. Support means the implementation
can perform the duties; enablement means the deployment has selected them.
Neither statement alone tells a reader which optional features a publication
uses. State the required profiles in deployment or integration documentation.
Runtime negotiation is not required unless a selected profile specifies it.
A promise to work with baseline-only clients requires a publication those
clients can consume. That includes the carrier: baseline clients read the
serialized JSON document, so a publication offered only inside an HTML page
requires a client that implements the
[`dca-profile-html-carrier` profile](spec--profiles.md#9-dca-profile-html-carrier-profile).

Consider the [`dca-profile-content-compression` profile](spec--profiles.md#6-dca-profile-content-compression-profile).
A publisher could support it and
choose gzip before encryption for its publications. A baseline-only client
could still be a conformant DCA client while being unable to decode those
publications. The publisher's description would distinguish "supports baseline
and compression" from "these publications require compression support". Gzip's
wide availability is not evidence that a particular DCA client implements the
profile.

An unsupported compression method prevents opening the affected item, as does
malformed transform metadata. These
[item failures](spec--content-protection.md#81-ordered-representation-layers)
add no mandatory protocol error code or plaintext fallback.

The publisher chooses whether to use compression for its intended clients and
integrations. If it promises access to baseline-only clients, it provides an
appropriate uncompressed publication or another usable alternative. Switching
off compression for future publications does not change copies already cached;
those still need a supporting client or a usable replacement. An issuer's
support alone does not establish what every client can decode. Choosing
compression before onboarding clients helps establish compatibility.

These descriptions help implementers state what they support and deployers
state whom they can serve. They create no separate badge, certification scheme
or runtime negotiation protocol.

## Choosing profiles

The baseline is the interoperability floor. Every DCA v1 role implements it:
the JSON delivery, one item content key for each issuer decision, and the
direct response over HTTPS. It is not a recommended deployment. Each optional
profile below is a separate choice with its own decider. For each one, keep
four statements apart: the implementation supports it, the deployment
enables it, a publication requires it of its clients, and an evidence run
exercised it.

Optional profiles make additional capabilities and wire-cost choices
interoperable without requiring every implementation to carry every mechanism.
A deployment can select only the paths it uses and, where the owning profile
permits it, omit redundant request or response material and the work needed to
process it. That can reduce transferred bytes, bandwidth cost and transfer
latency; it does not guarantee lower end-to-end latency. A simple
implementation can remain baseline-only, so each optional profile has to earn
its implementation and testing complexity with a complete, usable cross-role
path.

- **HTML carrier** (`dca-profile-html-carrier`)
  - **Who decides, and for what:** the publisher's publication arrangement,
    for each delivery.
  - **What it needs:** publisher and client implement the profile. Inert
    reserved `script` elements carry the JSON.
  - **When absent or unsupported:** a baseline-only client needs the JSON
    document from the same publication arrangement. When HTML is selected,
    the client refuses a malformed or repeated reserved carrier.
- **Browser origin** (`dca-profile-browser-origin`)
  - **Who decides, and for what:** the trusted contract between client host
    and issuer endpoint, for each route.
  - **What it needs:** the issuer admits only an observed origin that equals
    the signed one, and the endpoint answers CORS for that origin.
  - **When absent or unsupported:** an `Origin` header by itself selects
    nothing. A route that selects the profile is unusable for a caller that
    cannot meet it.
- **Period keys** (`dca-profile-period-keys`)
  - **Who decides, and for what:** trusted publisher configuration together
    with issuer policy, for each item and issuer route.
  - **What it needs:** a complete reusable-key alternative, and a client
    that meets the cache duties.
  - **When absent or unsupported:** keep a usable item content-key route
    when the publication promises baseline-only compatibility. Leaving that
    route out does not give a client period-key support.
- **Content compression** (`dca-profile-content-compression`)
  - **Who decides, and for what:** the publisher, for each item.
  - **What it needs:** the intended clients support the profile. The list
    `["gzip"]` on the item declares the choice.
  - **When absent or unsupported:** omit the list for baseline-only
    compatibility. An unsupported method and a malformed list are separate
    causes in host diagnostics, and both fail the item.
- **Client-bound result** (a client-bound custody profile)
  - **Who decides, and for what:** the trusted endpoint contract, the
    client's offer and the issuer's choice, for each response.
  - **What it needs:** both peers support the selected method, and the
    client admits the authenticated response.
  - **When absent or unsupported:** use direct delivery only where both
    sides permit that fallback. Missing optional bytes imply no fallback.

A browser subscription site commonly adds browser-origin admission. It adds
period keys where it wants their caching and accepts their reach, and the
HTML carrier for the deliveries it embeds in pages. These are selections a
deployment makes. DCA names no preset profile for them.

## One role, several hosts

```text
DCA client role
|-- Browser client
|   |-- direct delivery
|   `-- client-bound delivery
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
browser. A server that protects a new result as a DCA delivery is the
publisher of that delivery. An edge can gate a request, act as an issuer, broker
another issuer, or perform the complete client role. Calling all of these "edge DCA"
would hide the important differences.

For HTML articles, the [placement guide](guide--browser-content-presentation.md) separates
owner-selected browser rendering from independent reconstruction using the optional map.
A server producing article HTML still needs a serving policy: preserve source-URL meaning,
keep its report with the output and prevent retained carriers from restarting DCA placement.
Reconstructing declared slots does not reproduce every publisher script or widget.

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
- Obtaining a key is one condition for using a delivery. The client also
  reads the delivery's carrier, supports each item's content representation,
  reaches an endpoint that admits it, and accepts the response form that
  endpoint returns
  ([baseline profile](spec--profiles.md#3-dca-profile-baseline-profile)).

## Issuer integration and endpoint resolution

The publisher needs enough issuer information to seal content: a stable
`issuerName`, the current opening public key and `keyId`, trusted request caps
for publication preflight, and any selected profiles. Endpoint topology,
fallback order, health policy and reader credentials belong to deployment
routing rather than to each render.

The issuer hands over that record through any channel the parties trust: an
operator copying text, secure messaging, configuration management or an
authenticated management API. DCA v1 defines no provisioning message or
transport. The public key needs no confidentiality, but the publisher
authenticates what it receives
([envelopes Section 2.1](spec--sealed-key-envelopes.md#21-issuer-opening-key-provisioning)).

Mutually untrusted publishers need distinct issuer opening keysets. A
verified signed origin does not isolate their sealed values if the issuer
uses one shared opening private key.

For opening-key rotation, load and confirm the new private key on every issuer
node before giving its public-key record to the publisher. Only the public
record travels; never send the private key to the publisher. Keep the old key
while cached renders still carry its `keyId`. When a reader's cached page names
a key the issuer has already retired, the issuer reports `key_retired` for those
coordinates ([core Section 8](spec--core-protocol.md#8-failure-model)); a reload
can recover once it returns a fresh usable render referring to an accepted
opening key. A missing opening-key
version is an operational 5xx; an issuer alias outside the verified publisher's
scope is a terminal 4xx. For signing-key rotation, register the new
verification entry with every issuer, and with any gateway that verifies
renders, before the publisher signs with it; then overlap the old and new
registered verification entries while old signed renders still need new
unlocks. Retirement stops new grants for those renders but cannot revoke keys
already delivered.

Serving a new publisher origin needs no change to the signed-origin comparison,
though separately configured preflight policy or registration-level origin
restrictions may need an update before that origin can use the endpoint. DCA
defines no origin retirement; stopping an old origin is issuer deployment
policy. Renders signed for the old origin keep passing the origin comparison
while their signing key is still accepted. To stop new approvals for the old
origin, the issuer applies a registration-level origin restriction or denylist
([browser-origin Section 2.3](spec-profile--browser-origin.md#23-post-admission-order)),
or the publisher signs each origin under a separate signing key that can be
retired on its own. A render-age limit would need its own definition first:
`issuedAt` creates no validity window by itself
([core Section 4.1](spec--core-protocol.md#41-producer-form),
[period keys](spec-profile--period-keys.md#capability-lifecycle)). None of these steps
revokes a key or plaintext that a client already holds; such a client keeps
opening saved renders from that origin within its key's reach.

The article names the issuer. Its client integration supplies the unlock URL
and any fallback routes; the publisher's sealer does not configure those URLs.
An issuer can include endpoint defaults in its module or script and update
routing without publisher edits or resealing articles, provided the installed
integration receives the update. A frozen copy retains its old routing.

An issuer integration can register an endpoint route with the client host when
the publisher installs or loads that integration. In a browser deployment the
integration might be an issuer-supplied module or script. A server client can
use the same resolver boundary through local configuration or an installed
package. DCA does not require browser JavaScript as the registration mechanism.

The client intersects two sources before sending anything:

1. The publisher delivery says which issuers received sealed material and
   therefore have something they can open.
2. Trusted client-host configuration resolves each publisher-scoped
   `issuerName` to the endpoint or ordered endpoint route that may receive a
   request. The same alias under another publisher context may resolve to a
   different route, authentication mode or credential source.

This keeps endpoint changes and fallback policy out of each article without
requiring a publisher-operated synchronization service. The publisher still
chooses and trusts the installed integration. A third-party script running in
the publisher page has that page's script privileges, so deployments that do
not accept that trust use publisher-hosted code or server-side configuration.

The host establishes its publisher context from its trusted site or service
integration and the delivery it elected to process. A decoded but unverified
`resourceJWT` or readable `resource` mirror cannot establish that context.
Browser installation can supply that trusted site context; a server or edge
client also needs a trusted retrieval or source policy for the delivery it
serves to others. It does not gain the browser-origin check by sending a
synthetic `Origin`; its issuer route uses the applicable non-browser request
binding and caller authentication.
For each attempt, the host captures the selected route, request, logical client
context and applicable credential or explicitly anonymous mode. If a route or
credential changes while a response is pending, that response still belongs
to its captured operation; it cannot enter a successor's keys, cache or output.
The issuer independently verifies publisher claims and authorizes the caller.

If the publisher supplies no applicable material for an alias, or trusted
configuration supplies no usable route for it, the host sends no request for
that attempt. Missing local resolution is not an issuer refusal or a retryable
issuer outcome. It does not enable conditional fallback, though an independent
attempt already authorized by trusted configuration can proceed with that next
issuer's own publisher-authored material. A retained applicable key may still
open an item without a new unlock.

The [data format](spec--data-format.md#42-issuerdata) omits `unlockUrl` from
issuer entries. Clients ignore any carried value and use their installed
integration or explicit trusted endpoint configuration. This is required for
new acquisition, not a separate optional profile. Retained keys may still open
content without an endpoint. Removing the field adds no cryptographic guarantee
to a host that already selected its endpoint from trusted configuration.
Any portable discovery profile remains separate and must define its own trust
and disclosure rules. No page field may add an endpoint to a trusted route or
activate fallback. Server clients constrain configured endpoints under their
trusted routing policy; an untrusted delivery cannot become an SSRF target.

On an endpoint move, distribute the new client integration or configuration
before retiring the old route. The publisher delivery stays unchanged. A
redirect from the old endpoint does not supply fallback eligibility or change
the trusted route. Keep the old endpoint available while installed clients
that have not received the update still need it.

## Client context lifetime

The [core lifecycle rule](spec--core-protocol.md#221-logical-client-contexts-and-pending-work)
applies whether the client runs in a browser, native application or server.
The host selects the logical context, keeps each pending result with its
captured client and delivery, and ends a predecessor's eligibility before a
successor uses the same output target. Check eligibility immediately before
presenting plaintext, after the awaits needed to obtain it. An asynchronous
presenter carries that check through to its actual update.

The JavaScript `createBrowserClient` entry captures its client resolver,
request and delivery before transport. Replacing the application's variable
does not redirect an outstanding response. The application still owns
presentation and context lifetime; the facade has no retirement operation.
Use distinct client instances and distinct `cacheNamespace` values for mutually
untrusted contexts over one storage backend. An old write may finish in its
old partition. Do not recycle that partition for the successor while old work
can still write it. Intentionally shared caches require a trust and ownership
choice by the host. Retiring one context does not clear another live client's
cache and does not revoke bytes already returned.

### Session integration and optional account observation

This is an adjacent application contract for a publisher that composes a DCA
client with a session integration. It adds no DCA wire member, baseline login
requirement or account-menu requirement, and discloses no reader identity or
credential. The integration that owns login, logout and account switching
signals changes; the publisher associates that source with its affected client
contexts in its setup, rather than discovering accounts from keys. The provider
need not be the issuer. Conservatively retiring work on every unknown interval
is valid local policy.
[Browser-integration Section 4](spec-proposal--browser-integration.md#4-context-source)
defines the context source, suspension and replacement;
[Section 7](spec-proposal--browser-integration.md#7-companion-account-convention)
defines the optional account companion; the
[browser integration guide](guide--browser-integration.md#independently-loaded-scripts)
shows the wiring. These scripts keep ordinary same-origin access; the handoff
creates no security boundary against another page script.

## Browser client

The common DCA deployment runs the client in the reader's browser. This is the
shape covered by the
[browser-origin profile](spec-profile--browser-origin.md#2-browser-origin-requirements),
not a requirement that every DCA client be a browser. The browser reads the
encrypted publisher delivery, asks an issuer for missing capability, and opens
the item locally.

```text
publisher/cache -- encrypted render --> browser
browser -- unlock request -----------> issuer
browser <-- granted keys -------------- issuer
browser -- opens item locally
```

### Direct delivery

The issuer returns key bytes using the
[direct response representation](spec--response-binding.md#5-direct-representation).
This is the simplest route and works with item content keys or reusable
period keys. Browser code can retain and use the returned key within its
granted reach. It is a reasonable deployment when that exposure is accepted.

### Client-bound delivery

The client offers a recipient public key and the issuer wraps its answer for
that key, so a copied answer needs the matching private key; reach and
entitlement do not change. See
[issuer-to-client delivery](guide---overview.md#issuer-to-client-delivery) and the
[client-bound response specification](spec--response-binding.md#6-client-bound-common-representation).

Direct delivery is simpler to implement. Client-bound delivery limits reuse of a
copied response, but does not stop a reader-controlled browser from using its
capability or copying plaintext.

## Server client

A server can perform the same logical client work before serving an authorized
result to a reader. The server authenticates the reader under its own product
contract, obtains the DCA grant, opens the item, and then decides what to
deliver. A baseline server client reads the JSON delivery and needs no HTML
parser; it implements `dca-profile-html-carrier` only to extract a delivery from
an HTML page.

```text
publisher/cache -- encrypted render --> server client
server client -- unlock request ------> issuer
server client <-- granted capability -- issuer
reader <-------- authorized result ---- server client
```

The issuer identifies the admitted principal through the selected
authentication binding rather than treating a server process as an identity
by default
([core Section 2.3](spec--core-protocol.md#23-issuer)), and a deployment
chooses between two arrangements:

- **The issuer decides for each reader.** The server presents the reader
  through a binding the issuer trusts, and the issuer decides for that
  reader. Alice's request reaches the issuer as Alice and the issuer grants
  it; Bob's request is a separate decision.
- **The issuer grants to the service.** The issuer authenticates the service
  and grants what that service may receive. The issuer sees no reader; the
  service decides which of its callers receives the result.

In both arrangements, the service isolates its callers when it holds keys
or plaintext. Its release contract follows the selected arrangement: issuer
decisions for each reader, or service decisions for its callers. A service
that opened an item for Alice releases that key or plaintext to Bob only
when that contract admits Bob. The protocol's
[logical client context rule](spec--core-protocol.md#221-logical-client-contexts-and-pending-work)
requires isolation of retained capabilities between mutually untrusted contexts,
including pending work and late writes. This applies to item content keys and
plaintext as well as reusable period or chain keys. The service selects those
contexts and applies its release contract at each actual output side effect.

Item content keys narrow each grant to one item in one render. The service can keep the key or the plaintext and release
that render again without another issuer decision.

A server client whose output reaches other readers also decides which
sources it accepts deliveries from. Opening an item shows only that it
matches a held key; see
[what opening proves](spec--security-model.md#what-opening-proves).

Toward the reader, the server is a paywall or content service. Reader
sessions, plaintext delivery, watermarking and private response caches after
the item is opened are deployment behavior, not automatically DCA wire
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
shared-cacheable, and so the issuer stays separate from the publisher. The
issuer decides for each reader or grants to the service, as described under
[Server client](#server-client); when it grants to the service, release to
each reader is the service's decision. The paywall service now handles
content bytes and plaintext, rather than only an access decision.

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

After consuming a delivery as a DCA client, a service can produce either
of these outputs:

- **Resolved content.** The service returns the opened or transformed
  content under its own application contract. The unlock ends there for that
  output; the reader receives ordinary content from the service.
- **A new DCA delivery.** The service creates a separate delivery as a
  publisher. It generates content keys, encrypts the result, signs its own
  resource assertion and seals keys for an issuer under its own issuer and
  access arrangement
  ([core Section 2.1](spec--core-protocol.md#21-publisher)). A
  viewer-specific result such as a watermarked representation can travel
  this way when the transformation itself is the product requirement.

The service can publish a separate delivery using the existing protocol,
without a cryptographic extension.
The upstream publisher's assertion covers the upstream render and does not
authenticate the service's changes; the issuer and client of the new
delivery deal with the service as its publisher. Releasing that output to
the service's own readers remains the service's duty.

A defined extension or a private deployment contract is needed only when
independent implementations must agree on something base DCA does not
define, such as a binding between the two deliveries, a new key derivation,
client binding, representation or failure rule. Opening and resealing an
unchanged item is usually extra work with no new protection.

## Choices you can make separately

Describe a deployment on each axis instead of naming only its host:

| Axis | Examples | Question to settle |
| --- | --- | --- |
| Client placement | Browser, publisher backend, edge, paywall service, issuer-operated service | Where are keys used and items opened? |
| Issuer placement | Remote service, edge-hosted service, co-located with the server client | Who holds issuer private keys and entitlement policy? |
| Authority context | Issuer decides for each reader, issuer grants to the service | Which principal does the issuer admit, and who decides each release? |
| Reader result | Keys, plaintext, transformed plaintext, a new DCA delivery | What reaches the reader, and what can be copied? |
| Grant reach | Item content key, period key, selected extension | How much content does one grant open? |
| Cache boundary | Public encrypted render, private key response, private plaintext response | Which values may be shared between readers? |
| Fallback | Refuse, alternate issuer, deliberately weaker route, open publisher variant | Who authorizes a change in protection? |

These choices prevent false equivalences. An edge-hosted issuer that returns keys
to a browser is not the same as an edge client that returns plaintext. A
server-side client using a remote issuer is not the same as giving the server
issuer private keys.

Grant reach is also a choice about online control, reuse and cost:

- Cached `periodKey`: shared encrypted pages remain cacheable; the issuer is
  contacted once per applicable period or cache miss; reach after delivery is
  the granted access group and period. Least issuer traffic, broadest reusable
  key.
- Issuer-returned `contentKey`: shared encrypted pages remain cacheable; the
  issuer is contacted for each unresolved render; reach is that content item
  and render. More issuer traffic and availability dependence; plaintext can
  still be shared.

To require issuer contact when acquiring a new render's key, have the issuer
return item `contentKey` values and avoid reusable period grants; encrypted
publisher markup can still remain CDN-cacheable. That narrows reach to one item
and render per decision. It does not place an issuer decision before every
later release: a client or service that keeps the item `contentKey` reopens the
same render, and plaintext already opened needs no key.

## Which patterns make sense

| Pattern | Assessment | Why |
| --- | --- | --- |
| Browser asks a remote issuer and opens locally | Current browser deployment shape | Direct and selected client-bound delivery already fit the client role. |
| Edge gates an encrypted render; browser opens | Useful deployment | Adds request gating without changing DCA bytes; browser key exposure remains. |
| Edge brokers a remote issuer's browser-bound answer | Useful with explicit trust and request handling | Existing methods may compose, but an edge-session binding is not implied. |
| Edge acts as issuer; browser opens | Possible role placement | Moves issuer keys and policy to the edge; it is not merely a cache optimization. |
| Server client asks a remote issuer and returns plaintext | Useful deployment | Keeps keys out of that browser route and moves plaintext handling and bandwidth to the server. |
| Issuer and server client run together | Possible, with both roles in one service | Saves a hop but concentrates policy, issuer keys and plaintext custody. |
| Server opens, transforms and reseals | Useful when the transformation matters | Viewer-specific output can justify the second protection step. The service publishes the new delivery; only a new binding, derivation or representation needs an extension. |
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
plaintext, and the client stops. For conditional fallback, a configured route
may advance to another issuer only on an outcome that trusted route configuration
classifies as retryable; [core Section 5.3](spec--core-protocol.md#53-multiple-issuers) owns
which outcomes qualify, and
[unlock routing and fallback](guide--unlock-fallback.md#when-the-client-may-advance)
walks through them. An independently configured attempt remains separate.

These rules govern conforming-client coordination
([core Section 5.3](spec--core-protocol.md#53-multiple-issuers)); the issuer
authorizes each request independently. A reader can submit a request to any issuer
independently, whatever an earlier issuer answered, and each issuer
authorizes every request on its own verified claims and policy. Any weaker
emergency route is activated by trusted deployment policy, with its
different exposure understood in advance.

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

Both approaches can apply authentication and policy to each new acquisition.
A DCA issuer can check every item-key unlock and return only the content key
for one item in one render, applying IP, session or rate checks as required.
Server gating can apply those checks when delivering plaintext. Reusable group
or chain grants are a deliberate choice to authorize wider reach; they are not
required for item-key delivery.

Neither system retracts material already acquired. A downloaded plaintext copy
remains readable; a retained content key opens its matching item ciphertext in
that render, without granting access to other articles or new renders. Sharing
costs can differ: a DCA client can redistribute small usable keys while recipients
fetch public ciphertext, whereas a server-paywall attacker can relay plaintext
or share usable credentials. Choose grant reach and abuse controls for the
intended deployment.

A matching Origin and a genuine publisher signature do not prove where a
controlled HTTP client is viewing the content. The issuer's authentication and
authorization contract still applies; client-bound responses protect copied
responses without preventing an authorized controlled client from relaying
content. See the [security model](spec--security-model.md) for these boundaries.
Session, rate, concurrency and IP controls can restrict acquisition in either
approach; they also add operational work and can refuse legitimate readers.

DCA applies an established envelope-encryption pattern: the publisher encrypts
content under a data key and carries key access separately for authorized
recipients. Encrypted messaging encrypts a message with a random symmetric key,
then protects that key separately for each recipient; DCA similarly protects a
content key separately for each issuer. Managed envelope encryption protects a
data key under separately controlled key-encryption material; DCA uses the same
broad separation while assigning its actors different duties. These are
architectural analogies, not claims that those systems provide DCA's protocol
properties.
