# Delegated Content Access (DCA)

*DCA delegates access to encrypted, cacheable content to independent issuers
without publisher-issuer shared secrets or runtime coordination.*

DCA lets a publisher deliver the same encrypted render to every reader while
independent issuers decide which readers receive the capability needed to open
it. The publisher encrypts content at render time and seals key material for
configured issuers. Each issuer keeps its reader relationship, verifies the
signed resource context, applies its own policy, and returns only capability it
is willing to grant.

The publisher does not run issuer authentication flows, interpret
issuer-specific entitlement tokens, or keep issuer reader state. It applies
the content-access model and uses each issuer's configured opening material;
identity, entitlement, and reader policy remain issuer-side.

For the runnable reference, see [JavaScript](js/README.md). To verify this
checkout, see [Running the JavaScript checks](#running-the-javascript-checks).

## How it works

1. The publisher renders encrypted content items, signs the resource context,
   and seals key capability for configured issuers.
2. The client receives the same inert, cacheable delivery as every other
   reader: ciphertext, signed context, sealed keys, and issuer routes.
3. The client first tries matching key material stored from previous unlocks.
4. For unresolved items, it asks a selected issuer to unlock applicable
   capability.
5. The issuer verifies the publisher evidence, authenticates the reader when
   required or handles the request as explicitly anonymous, applies its own
   policy, and opens only authorized coordinates.
6. The client admits the issuer response, retains reusable capability when
   appropriate, and opens the granted content items.

The publisher can cache and share one sealed delivery; readers need an
issuer-opened capability before the protected content becomes readable. Access
decisions happen when the issuer processes an unlock request instead of at
render time. DCA blocks CSS-only bypasses but does not provide DRM: an
authorized reader can still copy plaintext or relay delivered access.

**Terminology:** Protected data is **sealed**, not locked: text behind locked
glass can still be read, while a safe hides its contents. Sealed
content remains opaque until opened with a key. The reverse is
**opening**. An **unlock** is the client-issuer exchange that applies access
policy and returns granted key capability. Names such as `contentKey` and
`periodKey` describe protocol roles, not cryptographic operations.

A `periodKey` is a **period key**: it wraps and opens item content keys at one
period coordinate.
A positioned `chainKey` is a **chain key** that derives period
keys back to the start of its bounded window. The Root operation's member at
that window's last position is the **root chain key**, the first chain key
derived for that window. There is no separate root key above it.

## Actors

| Actor | Role |
|-------|------|
| **Publisher** | Renders and delivers content. Encrypts protected items, signs their context, and seals keys for configured issuers. |
| **Issuer** | Controls access. Checks the publisher's signed content information, authenticates the reader when required or handles the request as explicitly anonymous, decides what that principal may access, and opens and returns only the key capabilities it grants. |
| **Client** | Receives the rendered content. First tries key capabilities stored from previous unlocks, then asks issuers for keys it is missing, and opens the content it is granted. |

## Background

Server-side content gating commonly makes the publisher integrate with each
access provider, participate in its authentication flow, interpret its
entitlement data, and personalize the response before delivery.

DCA moves that decision behind the encrypted delivery. The publisher integrates
with a stable content-access protocol; each issuer keeps its own reader
relationship and policy. The publisher still decides which content and routes
to offer, but it does not need issuer-specific reader state.

## Design goals

- **Independent access policy:** Each issuer authenticates its own readers and
  applies its own policy. DCA does not prescribe subscriptions, passes,
  metering, or another entitlement model.
- **Asymmetric delegation:** The publisher uses an issuer's public opening
  material. The issuer retains the corresponding private key; the parties do
  not establish a shared secret.
- **Separate issuer boundaries:** Each issuer can use independent key custody
  and policy. Compromising one such boundary does not reveal another issuer's
  private material.
- **No render-time issuer call:** Once configured, the publisher can create the
  shared encrypted render without calling an issuer or knowing the reader.
- **Cacheable delivery:** The encrypted publisher output is the same for all
  readers and can be cached without placing personalized plaintext at the
  shared edge.
- **Reusable capability:** Period keys can avoid a request for every render;
  the issuer chooses what capability to grant and the client retains admitted
  results where the selected profile permits it.
- **Explicit interoperability:** Selected profiles define wire structures,
  cryptographic transcripts, response protection, and failure behavior. Local
  alternatives require their own identified profile rather than silent
  substitution.

## Content items

A page or response can contain several independently encrypted content items.
Each item has its own key and may contain HTML, JSON, an image URL, or another
type of data. The publisher can offer access through the item's own key or
through a reusable period key. The publisher decides which items and which
routes to offer. At unlock, the issuer decides which offered key capabilities
to grant to that reader. Access varies through the granted keys, so DCA does
not require the publisher to render the protected content again for each
reader.

## Period keys

Without reusable period keys, a client normally needs an unlock to obtain a new
content key for each render. A `periodKey` is a reusable key for one
publisher, access group, and period coordinate. It can open every item key
protected through that matching route. It does not automatically cover content
merely because that content was published during the named period.

The client stores granted period keys and tries them again when later content
offers a matching route. Reuse reduces unlock requests, but the same capability
can open everything the publisher sealed under it. A key already delivered to
a client cannot be revoked.

An optional chain key can represent a bounded run of periods. From a granted
position, the client can derive period keys back to the start of that fixed
window, but not later positions or keys in another window. Issuers and clients
may instead support period keys only.

The publisher chooses the period label when it renders the content. An issuer
can open the capability carried for that label without recreating the label
from its own clock, although it may still consider time when applying policy.

## Data flow

**Publisher → Client** (at render time):

- Encrypted content.
- Signed information about the content and render (`resourceJWT`).
- Issuer routes and sealed keys that only the matching issuer can open.
- No plaintext or usable content or period keys.

**Client → Issuer** (unlock request):

- The publisher's `resourceJWT`, relayed unchanged.
- That issuer's sealed keys for content the client cannot already open.
- The names and coordinates needed to identify the requested keys. The request
  names coordinates; the issuer decides whether to grant them.

**Issuer → Client** (unlock response):

- Only the keys granted by the issuer's access decision.
- Content keys for individual items, reusable period keys, or an optional
  bounded chain key.

**Never exchanged:**

- The issuer's private opening key stays with the issuer.
- A publisher `keyDerivationSecret`, when the chain-key profile uses one, stays
  with the publisher.

**The publisher limits an issuer's grants by choosing which keys to seal.**
Several issuers can receive authority over the same content. At unlock, the
client names coordinates, while each issuer independently decides which of
those keys the reader receives.

## Key layers

The three key layers control content, reuse, and who decides:

| Layer | Dimension | Controls |
|-------|-----------|----------|
| **`contentKey`** | What | One protected item in one render |
| **`periodKey`** | Reuse | Matching content across renders for one publisher, access group, and period |
| **Issuer key pair** | Who decides | Selects the issuer that may decide access; `issuerPublicKey` seals and `issuerPrivateKey` opens |

The public and private keys are two halves of one issuer opening key pair. The
publisher chooses who may decide by choosing the key pair. The issuer then
authenticates the reader and applies policy before using its private key to open
the capabilities it grants. One unlock response can contain item keys, reusable
period keys, or both.

### Layers of encapsulation

#### Item `contentKey` delivery

The issuer returns a content key for one item in one render. A client that
supports the item's content representation opens that item with the key.

<pre>
<b>content</b>
  ← sealed with <b>contentKey</b>
    ← sealed with <b>issuerPublicKey</b>
</pre>

Sealing (publisher, at render time):

- Publisher seals the item with its content key.
- Publisher seals the content key with `issuerPublicKey`.

Opening (client, at page load):

- Client asks the issuer to unlock the sealed content key.
- After granting access, the issuer opens it with `issuerPrivateKey` and
  returns the content key.
- Client opens the item with the content key.

#### Reusable `periodKey` delivery

Reusable: the issuer returns a period key. The client uses it to open a
matching sealed content key, then opens the item. It can store the period key
and use it again for matching content.

<pre>
<b>content</b>
  ← sealed with <b>contentKey</b>
    ← sealed with <b>periodKey</b>
      ← sealed with <b>issuerPublicKey</b>
</pre>

Sealing (publisher, at render time):

- Publisher seals the item with its content key.
- Publisher seals the content key with a period key.
- Publisher seals period-key capability with `issuerPublicKey`.

Opening (client, at page load):

- Client asks the issuer to unlock the sealed period-key capability.
- After granting access, the issuer opens it with `issuerPrivateKey` and
  returns the period key.
- Client opens the sealed content key with the period key.
- Client opens the item with the content key.

An optional chain key changes how period keys are obtained.
It does not add another sealing layer or change what a period key opens.

## Security model

DCA requires an issuer-approved key to read protected content. It suits
paywalls intended to require payment. An authorized reader can still copy
decrypted content. The publisher ships ciphertext instead of plaintext
hidden by presentation logic. Removing CSS,
editing markup or disabling a script reveals nothing, because the page holds
ciphertext and no usable key. A script that can reach an authorized
reader's key or opened content can read what that reader can. DCA does not stop an authorized reader from
copying that key or the content it opens. Schemes that keep control online or tailor content delivery to each reader
can make copying harder, with greater complexity and often higher server or
cloud cost than sharing one cached render.

### Choosing the operating boundary

| Approach | Publisher delivery | Issuer contact | Reach after delivery | Main trade-off |
|----------|--------------------|----------------|----------------------|----------------|
| DCA, reusable `periodKey` | Shared encrypted content | Once per matching period or cache miss | Matching content in the granted access group and period | Fewer issuer calls, broader reusable key |
| DCA, item `contentKey` | Shared encrypted content | Each unresolved render | One item in one render | Narrower key, more issuer traffic and availability dependence |
| DCA, client role on a server or edge | Shared encrypted source; private authorized response | Each protected request, or a deployment-defined private cache | Only the authorized result released by the gate | Server-side paywall boundary with shared encrypted source and a separate issuer |
| Server gating without DCA | Usually personalized plaintext | Each protected request | Server decides before each delivery | More origin or edge work and less shared caching |
| DRM or attestation | Separate product architecture | Product-specific | Product-specific | Greater platform, operational, and user cost |

The DCA client role can run in a browser or native application. A publisher
backend, edge worker or paywall service can also authenticate the reader,
perform the DCA client work, and return an authorized result without
delivering DCA keys to the browser. The host running the client role holds the granted keys. From the
reader's side a server client is a conventional server-side paywall with the
same pre-delivery access boundary; DCA continues behind it to keep the stored
render encrypted and cacheable and to keep the issuer separate from the
publisher.

Through the selected authentication binding, the issuer can decide for each
reader or grant to the service. A service that receives the grant
decides what to release to its own callers. See the
[server-client deployment patterns](docs/guide--deployment-patterns.md#server-client).

DCA can mix item content keys and reusable period keys across content items.
To require issuer contact when acquiring a new render's key, have the issuer
return item content keys and avoid reusable period grants. That narrows each grant to one item in
one render. A client or service that keeps the key or the opened content can release
that render again without another issuer decision. Neither browser nor server placement prevents an authorized
reader from copying content after it is delivered.

### Trust boundaries

| From | To | Trust given |
|------|----|-------------|
| Publisher | Issuer | The publisher caps an issuer's grants by what it seals |
| Issuer | Client | Granted keys can be used and copied; delivery cannot be taken back |
| Publisher | Client | Encrypted content and protected key material, but no usable keys |

The publisher limits what each issuer can possibly grant. The issuer
authenticates the reader and decides which of those keys to return. Once the
client opens the content, it has plaintext and can copy it.

### Protection scope

**What DCA protects against:**

- Revealing protected content by viewing source, removing CSS, or disabling
  presentation code.
- Opening a copied encrypted page without a matching key. The copied page stays
  ciphertext and contains no hidden plaintext.
- **Unauthorized widening through request manipulation or replay:** Changing
  names or coordinates, relabeling or moving sealed keys, or replaying an
  exchange cannot expand access beyond what the publisher supplied and the
  issuer granted.
- Releasing a missing key without an issuer authorization decision. Authorized
  readers can automate acquisitions and share or reuse the keys they receive;
  a period-key grant can open every retained matching item without another
  issuer call.

These protections come from the signed publisher context that the issuer
verifies, BIND on publisher-sealed keys, registration-scoped opening keys,
and the issuer's own authentication and policy. BIND checks the coordinate
when the issuer opens a sealed key; the selected response binding protects
the issuer's answer on its way to the client. See the
[full security model](docs/spec--security-model.md) for the exact boundaries and
failure cases.

Opening an item verifies it against a key the client holds. Establishing publisher authorship or the source of a copy
requires separate evidence; see [what opening proves](docs/spec--security-model.md#what-opening-proves).

**What DCA does NOT protect against (not DRM):**

- An authorized reader copying or sharing opened content.
- A reader sharing returned keys or access. Client-bound delivery encrypts
  the answer for one recipient key that the client offered first, so a copied
  answer alone is not usable. The reader who controls the client, whether a
  browser, a native application or a server, can still use or relay the
  capability, and needs no root access to do so.
- Screen capture or copy and paste of rendered content.
- Scripts or extensions reading plaintext after opening. Plaintext must reach
  the application or DOM to be used.

### Asymmetric trust model

The publisher uses an issuer's public key. The matching private key stays with
the issuer. This separates their key custody, but each party still has its own
trusted material. Stealing that material compromises a trust root; an
authorized reader reusing or sharing a granted capability acts within that
capability's reach:

- **Publisher breach:** The publisher already has the plaintext. Theft of its
  signing key can forge publisher information, but does not reveal an issuer's
  private key or bypass issuer reader policy by itself. Theft of period keys
  exposes their matching content; theft of an optional chain-key
  `keyDerivationSecret` has the wider reach defined by that chain-key
  generation.
  Issuers retire compromised publisher signing keys, which stops new
  approvals that rely on them, and publishers rotate affected key material
  for future renders. Neither step retracts keys or plaintext already
  delivered.
- **Issuer breach:** Theft of an issuer private key exposes publisher material
  sealed under that opening key. Independently keyed issuers remain separate.
  Publishers that share one issuer opening key set are mutually trusted at
  that boundary. Rotation protects future material but cannot retract keys or
  plaintext already delivered.
- **No publisher-issuer shared secret:** Publisher-to-issuer sealing uses a
  public-key pair instead of placing the same secret at both the publisher and
  issuer. This keeps one issuer's private material away from the publisher, and
  compromise of one issuer key pair does not reveal another independently
  keyed issuer's private material.

## Operational considerations

**Search indexing:** A publisher that wants search crawlers to index protected
content can keep an open variant for verified crawlers and a DCA-protected
variant for readers. Both variants can use the same resource URL when an
explicit cache key keeps them separate. Trusted
infrastructure verifies crawlers and selects the open variant. The routing and
verification details are publisher deployment concerns, not DCA protocol
behavior.

**Issuer failover and load shedding:** A client can try another issuer route
offered for the same content; each issuer authorizes the request it receives
independently. An issuer can also activate a deliberately weaker
emergency policy to keep content available when its issuer service is
overloaded or cannot reach its usual entitlement system. Item content keys
keep the content encrypted and limit each grant to one item and render. With
direct response delivery, an answer can be reused only inside a safe
authorization cache partition.
Client-bound answers are specific to one client capability and are not shared
cache entries. Reusable period keys reduce later issuer calls further, but
grant broader reach.

Publishing an unencrypted fallback is a separate, explicit publisher decision,
not an automatic DCA failure mode. A publisher may expose that last-resort
choice through an editorial or administrative control so an operator can weigh
availability, access precision, server cost, and content protection during an
outage.

**JavaScript-disabled users:** Protected items remain ciphertext and cannot be
opened. The page may still show unprotected content or a publisher-provided
fallback message. Unlike a soft paywall, the protected plaintext is not already
present in the page for a CSS or DOM change to reveal.

## Running the JavaScript checks

Use Node 22.22.2 and pnpm 10.23.0, as pinned in `js/.node-version` and
`js/package.json`, plus headless Chromium with its runtime libraries. The
[JavaScript setup instructions](js/README.md#browser-prerequisite) describe browser
installation and executable/library selection. With those prerequisites installed
and `pnpm` available on your PATH, run from this repository's root:

```sh
pnpm --dir js install --frozen-lockfile --ignore-scripts
sh js/check
```

The command checks JavaScript lint, formatting, admitted types, source
boundaries, reference behavior and experiments. It does not run PHP, recorded
vector checks, portable contracts or cross-runtime conformance. Exit 0 means
all required stages passed; 1 means a stage failed; 2 means a required check
could not run or verified less than intended.

The [JavaScript instructions](js/README.md) explain setup and separately
selected commands. See [verification](verification/README.md) for independent
evidence checks; passing `sh js/check` does not establish full DCA conformance.

## Documents

| Document | Scope |
|----------|-------|
| [Design overview](docs/guide---overview.md) | Deeper explanation of how DCA's parts fit together |
| [Deployment patterns](docs/guide--deployment-patterns.md) | Browser, server, edge, and hybrid ways to place the DCA client role |
| [Article placement](docs/guide--browser-content-presentation.md) | Owner-selected browser rendering, template-authored maps and independent article reconstruction |
| [Period-key integration](docs/guide--integration--period-keys.md) | Publisher, issuer, and client path with runnable reference evidence |
| [Specification overview](docs/spec---overview.md) | Normative document map, conformance boundaries, and reading order |
| [Profiles](docs/spec--profiles.md) | The `dca-profile-baseline` profile every implementation starts from, and the optional profiles |
| [Security model](docs/spec--security-model.md) | Security promises, assumptions, limitations, and operating choices |
| [Data-format example](docs/design--data-format--example.md) | Worked publisher delivery and wire example |
| [JavaScript reference](js/README.md) | Reference implementation, runnable demonstration, tests, experiments, and the public check command |
| [Verification](verification/README.md) | Stock-library primitive bridges on pinned runtime lanes, including JavaScript on Node, Deno, Bun and workerd, recorded wire vectors, and shared fixtures |

## Status

DCA is a public working draft and may change before v1. Current draft
priorities are listed in
[roadmap--draft-period.md](roadmap--draft-period.md).
[CHANGELOG.md](CHANGELOG.md) records key-opening changes since the
21 September 2026 public draft and the roles that need updated code.

Developed at Labrador CMS AS. Specification editor: Geir Bostad.

Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Copyright 2026 Labrador CMS AS.
