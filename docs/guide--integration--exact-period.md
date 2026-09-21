# Integrating exact period keys

Status: Informative Draft

This guide is the shortest practical route through the
[`dca-v1-exact-period`](spec--profiles.md#5-dca-v1-exact-period-profile)
profile. It assumes the baseline profile plus exact period keys: a publisher
wraps item keys for a period, an issuer grants an authorized exact
`periodKey[t]`, and a client retains that key so later matching content can
open without another issuer call.

The [period-key guide](guide--period-keys.md) explains the model. The
[period-key specification](spec--period-keys.md) and the specifications it
references remain authoritative.

## The result to preserve

A complete exact-period integration has this observable path:

1. The publisher creates a fresh `contentKey` for each item and wraps it under
   one or more exact period keys.
2. The page carries the item ciphertext, those item-key wraps, and the same
   exact period keys sealed to each issuer that may grant them.
3. The client asks an issuer only for content it cannot already open and
   relays the selected exact-period material.
4. The issuer verifies the publisher material, applies its own authentication
   and policy, and returns only the authorized exact leaves.
5. The client admits and retains the returned key, opens the first item, and
   can open another item with the same publisher, `accessGroup`, generation,
   and `t` without another unlock. The
   [generation rules](spec--period-keys.md#51-period-key-family-generation-and-window-identity)
   keep reused coordinates in one key lineage.

The reference scenario
[`scenario.test.js`](../js/v1/test/scenario.test.js) rigs that complete
reuse story: article A triggers one unlock whose response includes exact keys,
then article B opens with the retained overlap key while the issuer-call count
remains one. Article A itself uses the independently authored direct route in
that scenario; `period-prefix.test.js` separately exercises initial and later
opening through an exact grant.

## Reference code to start from

- **Client:** use
  [`copy-manifest--client.json`](../js/v1/copy-manifest--client.json) at a
  pinned repository revision. It is the supported source-copy boundary.
  [`createBrowserClient.js`](../js/v1/integration-client/createBrowserClient.js)
  composes the client core, page reader, cache, request builder, response
  admission, and content opener. Keep the selected directories together so
  their relative imports continue to resolve.
- **Publisher:** start from
  [`core-publisher/`](../js/v1/core-publisher/) and
  [`writeMarkupDelivery.js`](../js/v1/adapter-publisher/writeMarkupDelivery.js).
  The reference does not yet publish a supported publisher copy manifest or
  integration entry.
- **Issuer:** start from
  [`IssuerEngine.js`](../js/v1/core-issuer/IssuerEngine.js),
  [`IssuerProcessor.js`](../js/v1/core-issuer/IssuerProcessor.js), and the
  adapters under [`adapter-issuer/`](../js/v1/adapter-issuer/).
  [`UnlockEndpoint.js`](../js/v1/ports/UnlockEndpoint.js) is the reusable port
  between admitted application input and the processor. The reference does
  not yet publish a supported issuer copy manifest or integration entry.

The demonstration
[`Publisher`](../js/v1/demo/actors/Publisher.js),
[`Browser`](../js/v1/demo/actors/Browser.js), and
[`IssuerServer`](../js/v1/demo/actors/IssuerServer.js) show how the pieces are
rigged with keys, policy, storage, and transport. They are examples, not
deployment APIs. Do not copy demo or test code into a role artifact.

## Operations by role

These lists are the implementation path, not a second specification. Each
operation links directly to its normative owner.

### Publisher

1. Generate a fresh 16-octet item `contentKey`, encrypt the item with
   AES-128-GCM, and retain its `nonce` and `aad` under
   [the protected-item transcript](spec--content-protection.md#3-base-protected-item-transcript).
2. Obtain the exact 16-octet `periodKey[t]`, then wrap the item key under it
   using the
   [exact-period wrapping transcript](spec--content-protection.md#4-base-exact-period-content-key-wrapping).
3. Build BIND from the render and exact coordinate, then seal the exact key to
   each issuer using its provisioned public key. The
   [envelope model](spec--sealed-key-envelopes.md#2-envelope-model),
   [BIND](spec--sealed-key-envelopes.md#3-bind), and the selected
   [ECDH P-256](spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope) or
   [RSA-OAEP](spec--sealed-key-envelopes.md#5-rsa-oaep-envelope) algorithm
   define that operation.
4. Place the item record, wraps, issuer envelopes, endpoint, and key identifier
   in [the delivery object](spec--data-format.md#4-the-dca-data-object).

### Issuer

1. Admit HTTPS JSON and, when selected, browser Origin/CORS in the order
   required by the
   [endpoint binding](spec--browser-http-binding.md#3-dca-https-json) and
   [browser profile](spec--browser-http-binding.md#4-dca-browser-origin-profile).
2. Select the publisher registration from the JWT header hint, verify the exact
   `resourceJWT` under
   [core verification](spec--core-protocol.md#42-verification-and-registration),
   then resolve `issuerName` and `keyId` only within that authenticated
   registration under
   [opening-key scope](spec--core-protocol.md#63-opening-key-scope-and-bind).
3. Construct the presented coordinates, authenticate the reader, and ask
   issuer policy what may be granted under
   [presented coordinates](spec--core-protocol.md#61-presented-coordinates)
   and [authentication and policy](spec--core-protocol.md#62-authentication-and-policy).
   The [metering integration guide](guide--integration--metering.md) shows the
   reference policy callback and its exact-period trade-off.
4. Rebuild BIND from verified facts and open only granted envelopes. Follow
   [core opening scope](spec--core-protocol.md#63-opening-key-scope-and-bind)
   and the envelope specification's
   [opening and failure rules](spec--sealed-key-envelopes.md#6-opening-and-failure).
5. Produce the [core issuer result](spec--core-protocol.md#7-core-issuer-result),
   including the distinction between denied coordinates and
   [per-coordinate errors](spec--core-protocol.md#71-per-coordinate-errors),
   then encode one selected
   [response representation](spec--response-binding.md#4-selection-and-agreement)
   over the authenticated channel. The baseline
   [direct representation](spec--response-binding.md#5-direct-representation)
   returns base64url key bytes; a client-bound method adds its own duties.

### Client

1. Read one admitted delivery, find what retained capability already opens,
   and build a request only for unresolved items under
   [the core request rules](spec--core-protocol.md#5-core-unlock-request).
   Include a client offer only when its optional response method is selected,
   as described by [optional offers](spec--core-protocol.md#52-optional-offers)
   and [response selection](spec--response-binding.md#4-selection-and-agreement).
2. POST the request to the authenticated endpoint without automatically
   following a redirect under the
   [endpoint and channel rules](spec--browser-http-binding.md#31-endpoint-and-channel).
   Retain the exact request association until response admission completes
   under [the request rules](spec--browser-http-binding.md#33-request).
3. Admit only coordinates associated with that request and enforce the
   selected response representation under
   [the common response rules](spec--response-binding.md#3-inputs-and-common-response-form),
   [replay and composition](spec--response-binding.md#9-replay-caching-and-composition),
   and [failures](spec--response-binding.md#10-failures).
4. Retain admitted exact keys under the
   [exact-period requirements](spec--period-keys.md#55-base-exact-period-requirements).
   Try matching cached wraps and unwrap the item `contentKey` under
   [content-key resolution](spec--content-protection.md#52-resolving-a-content-key)
   and [cached wrap attempts](spec--content-protection.md#53-cached-wrap-attempts).
5. Authenticate and decrypt the item before releasing plaintext, then reverse
   selected content encodings under
   [content opening and containment](spec--content-protection.md#54-content-opening-and-containment).

## Implementing the client store

[`PeriodKeyCache.js`](../js/v1/adapter-client/PeriodKeyCache.js) is the
reference exact-key store. Its public methods and `CacheStorage` type define
the implementation seam. The browser entry lets
[`composeClient.js`](../js/v1/integration-client/composeClient.js) construct it
from `storage`, `cacheNamespace`, and `cacheKeyBy`, or pass a complete `cache`
of their own. The
[JavaScript reference README](../js/v1/README.md#publisher-client-and-issuer-artifacts)
explains how those options reach the browser entry.

The store behavior has five parts:

1. Response admission supplies exact capabilities to the resolver. The resolver
   files admitted candidates by publisher, family, and byte-identical `t`; an
   item lookup asks only for candidates at its authored coordinate.
2. `cacheNamespace` isolates logical clients that share one storage backend.
   The publisher remains part of every stored family. A deployment may add an
   issuer partition with `cacheKeyBy`, but that changes lookup eligibility,
   not the cryptographic reach of key bytes already delivered.
3. With no storage adapter, the reference cache is in memory. Its persistent
   adapter contract is asynchronous `get`, `set`, `keys`, and `remove` over
   strings. That adapter stores raw exact-key bytes; a client-bound
   non-extractable handle needs a cache and storage design that can retain
   handles instead.
4. A coordinate may hold rival key generations. The reference tries the most
   recently filed candidate first, retains only bounded candidates, and
   applies its total capacity across families. These are local bounds, not
   wire or authorization limits.
5. Storage read-modify-write can lose a concurrent same-family write. The
   reference keeps a tab-local record and exposes caller-invoked `reconcile()`
   to restore the union. A host chooses when to invoke it or supplies a store
   with stronger coordination.

An exact capability remains cryptographically usable after its labeled
interval. The
[normative retention rules](spec--period-keys.md#55-base-exact-period-requirements)
make later retention and time-based eviction host policy, and the
[period-key guide](guide--period-keys.md#reach-retention-and-revocation)
explains why eviction causes an ordinary miss rather than revocation. The
reference cache has no time expiry unless a host constructs it with both a
clock and an eviction callback. `createBrowserClient()` deliberately does not
accept a clock; a host needing that policy passes its own configured cache.

## Cryptography at a glance

- Item encryption and exact-period item-key wrapping use AES-128-GCM.
- `contentKey` and exact `periodKey[t]` values are 16 octets.
- Publisher-to-issuer envelopes use either P-256 ECDH followed by
  AES-256-GCM, or RSA-OAEP with SHA-256 and a modulus of at least 2048 bits.
- Baseline issuer responses carry direct key bytes inside authenticated,
  confidential HTTPS. Client-bound response methods add their own wrapping;
  they do not replace that channel.

## The JSON path

The [worked data-format example](design--data-format--example.md#dca-data-json)
shows all of these members with readable placeholders.

- `contentData[contentName]` describes one encrypted item. Its `nonce` and
  `aad` accompany the ciphertext in the matching sealed-content carrier.
- `contentData[contentName].keys[accessGroup][]` carries candidate item-key
  wraps. Each candidate names `t`; its `nonce` and `key` wrap that item's
  `contentKey` under the exact `periodKey[t]`.
- `issuerData[issuerName].sealed.periodKeys[accessGroup][t]` carries the same
  exact period key sealed for that issuer.
- `issuerData[issuerName].sealed.contentKeys[contentName]` is the independent
  baseline direct route. Its presence does not select or disable the exact
  route.
- `issuerData[issuerName].unlockUrl` names the publisher-carried default
  endpoint. `keyId` identifies the issuer opening-key record within the
  verified publisher registration.
- The client unlock request relays `version`, `issuerName`, the signed
  `resourceJWT`, `keyId`, unresolved `sealed.contentKeys`, and selected
  `sealed.periodKeys`.
- A successful exact-period result places granted leaves under
  `keys.periodKeys[accessGroup][t]`. The client associates the response with
  its request before retaining or using any returned key.

Keys and ciphertexts remain base64url strings on the wire. Do not infer
authority from object names, array order, the client clock, or mere member
presence; use the validation and binding rules in the normative documents.

## What exact-only code does not process

An exact-period implementation does not need period-chain behavior. Unless
the period-chain profile is separately selected, it treats these extension
members as unknown and gives them no route meaning:

- top-level `periodChain`;
- `sealed.periodChainKeys` in publisher delivery or a request; and
- `keys.periodChainKeys` in an issuer result.

Unknown members follow the common JSON rule in
[the data-format specification](spec--data-format.md#2-common-json-rules).
Ignoring a chain member does not mean ignoring the surrounding object,
resource limits, or a selected exact member. The direct `contentKeys` route is
also not chain material: it remains a baseline alternative when authored and
selected.

The [profile rules](spec--profiles.md#51-dca-period-chain-v1-profile) assign
the additional roles and paths selected for period-chain processing. The
[period-chain guide](guide--period-key-chains.md) explains that model, and the
[reference extension README](../js/v1/extensions/period-chain/README.md)
maps it to the separate chain cache and extension tests. Exact keys returned
on a chain-capable route still enter the ordinary exact-key store.

## Supplying exact keys at the publisher

The simplest publisher source generates independent random 16-octet exact
keys. A publisher may instead use the canonical period-chain construction
privately to regenerate the same exact leaves. That choice is opaque to an
exact-only issuer and client and does not select the period-chain profile.

Do not emit `periodChain` or `periodChainKeys` merely because the publisher
used chain derivation internally. Emit those members only for a separately
selected chain route whose affected roles implement its duties.

## Opened bytes and page presentation

The client core stops at authenticated, decoded `Uint8Array` bytes.
`ContentRepresentationOpener.open(...)` returns those bytes, and the item's
`contentType` tells the host how the publisher described them. Under the
[content-handling boundary](spec--content-protection.md#7-deferred-ciphertext-and-content-handling),
v1 does not cryptographically authenticate `contentType`, so it remains
handling metadata rather than proof of the plaintext's type. Neither value
selects a DOM target or grants permission to execute code.

The current `createBrowserClient()` entry exposes its reader, delivery view,
resolver, opener, and one-issuer `unlock` operation. The host still performs
the final sequence: read an item record and ciphertext, resolve or unlock its
content key, call the opener, and hand `{ contentName, contentType, bytes }` to
its own renderer. The WIP
[browser presentation guide](guide--browser-content-presentation.md) shows
one early illustration of a publisher callback for that handoff. It is not a
selected integration interface. The
`renderOpenedContent(...)` call below is a local publisher placeholder; a
publisher experimenting with the sketch may adapt that local call to
`presentation.presentOpenedContent(...)`. The exact-period handoff does not
adopt the sketch's version or lifecycle fields. A high-level
`open(contentName)` convenience remains reference-integration work; neither is
an exact-period protocol step.

This is the complete handoff for one item after constructing `client` with
`createBrowserClient()`:

```js
const contentName = "bodytext";
const { missing } = await client.resolver.resolve(client.dcaData, [contentName]);

if (missing.length > 0) {
  const answer = await client.unlock(missing);
  if (answer.status !== 200) throw new Error(`DCA unlock answered ${answer.status}`);
}

const record = client.dcaData.contentDataFor(contentName);
const ciphertext = client.reader.extract(contentName);
if (!record || ciphertext === null) throw new Error(`DCA page carries no ${contentName}`);

const bytes = await client.opener.open({
  record,
  contentName,
  ciphertext,
  aad: record.aad,
  resolveKey: async () =>
    (await client.resolver.contentKeyWithOriginFor(client.dcaData, contentName))?.key,
});

await renderOpenedContent({ contentName, contentType: record.contentType, bytes });
```

`renderOpenedContent` is application code, not a DCA operation. It should map
the admitted `contentName` to a host-configured target and dispatch on an
allowed `contentType`. For example, decode text into `textContent`, parse and
schema-check JSON, or create a `Blob` for an admitted binary type. Treat
`text/html` as publisher content that still needs the host's normal trust and
sanitization policy; do not pass arbitrary opened bytes to `innerHTML`, derive
a selector from `contentName`, or activate scripts merely because DCA opened
the item.

Placement remains host-owned. A host may map one content name to a whole
article container, a phrase-level target, several targets, or a framework
component. DCA does not insert HTML, sanitize fragments, hydrate components,
or run scripts. Script activation is explicit host policy and must obey the
page's CSP; it is never an automatic consequence of successful decryption.

## Run and inspect the reference evidence

From the repository root, run the current exact-period simulation and print
its compact, boundary-focused flow plus a decoded JWT inspection view:

```sh
node --input-type=module -e 'const { run } = await import("./js/v1/demo/browser/scenario.js"); const { flow, inspection } = await run(); console.log(JSON.stringify({ flow, inspection }, null, 2))'
```

The `flow` value has this shape:

```json
{
  "publisherDelivery": {
    "dcaData": {},
    "sealedContent": {},
    "markup": "..."
  },
  "unlockRequest": {
    "unresolvedContentNames": [],
    "body": {}
  },
  "unlockResponse": {
    "status": 200,
    "body": {}
  }
}
```

`publisherDelivery.dcaData` and `publisherDelivery.sealedContent` are the page
carriers. The client reads those values, resolves what its cache already
covers, and produces `unlockRequest.body`; that request is exactly what the
issuer receives. The issuer's JSON result appears as `unlockResponse.body`.
`unresolvedContentNames` is the client-local selection that produced the body;
it is context for the boundary rather than a transmitted request member.
Client-local retention and content opening remain in the full `steps` event
history.

`inspection.resourceJWT.header` and `.payload` are decoded for human
inspection only. Decoding does not authenticate them; the issuer verifies the
compact token's signature before using those values.

To print the full diagnostic event history instead:

```sh
node --input-type=module -e 'const { run } = await import("./js/v1/demo/browser/scenario.js"); console.log(JSON.stringify(await run(), null, 2))'
```

That output includes each render's `dcaData`, sealed-content map, markup and
decoded `resourceJWT`, followed by the unlock request, unlock response, cache
observations and opened plaintext. The page's two markup JSON carriers are at
`flow.publisherDelivery.dcaData` and `.sealedContent`; they are the exact
values the markup writer used. The simulation is an inspection aid over demo
actors, not a supported integration API or independent conformance evidence.

That live scenario generates non-extractable signing and issuer keypairs and
does not export their private halves. For fixed, explicitly public test
material, inspect
[`verification/fixtures/protocol-v1/seal-ecdh.json`](../verification/fixtures/protocol-v1/seal-ecdh.json).
Its input contains the publisher signing private/public JWKs, issuer opening
private/public JWKs, exact period keys, plaintext inputs, clock and deterministic
sealing material. Its expected section contains `dcaData`, sealed content,
bindings, content keys, exact keys and opened plaintext. These secrets are
published test fixtures and must never be used in production.

The fixture and live trace are complementary. The fixture supplies stable
inputs and publisher output; the trace shows the complete request, issuer and
client flow. The repository does not yet ship one supported playground command
that combines both into a replace-one-stage artifact bundle.

Run the focused evidence tests from the repository root:

```sh
node --test js/v1/test-profiles/dca-v1-exact-period.test.js
node --test js/v1/test/scenario.test.js
node --test js/v1/test/period-prefix.test.js
node --test js/v1/test/dca-request-builder.test.js
node --test js/v1/test-reference/adapter-client/periodkeys.test.js
node --test js/v1/test/cache-eviction.test.js
node --test js/v1/test/storage-concurrency.test.js
```

- `dca-v1-exact-period.test.js` is the complete reference profile scenario. It
  disables direct delivery, selects exact relay and issuer input independently,
  opens one item through the issuer, and opens the next from retained
  capability without another issuer call.
- `scenario.test.js` proves cross-render reuse: one response retains the
  overlap key that opens the next render without another issuer call.
- `period-prefix.test.js` shows the issuer granting a bounded prefix of the
  presented periods, the client opening through that exact grant, retaining
  only delivered keys, and later content opening from the retained capability.
- `dca-request-builder.test.js` exposes the request JSON and checks the exact
  maps copied from publisher delivery.
- `periodkeys.test.js` owns exact-store admission, lookup, duplicate and rival
  handling, persistence order, local bounds, and the no-second-unlock reuse
  path.
- `cache-eviction.test.js` moves across periods and family generations. It
  shows what remains readable before and after capacity eviction, including
  the issuer call caused by an ordinary miss.
- `storage-concurrency.test.js` owns the asynchronous adapter contract,
  same-family races, explicit reconciliation, capacity, optional clock policy,
  and logical-client namespace isolation.

These are JavaScript implementation tests, not independent conformance proof.
The [profile-test index](../js/v1/test-profiles/README.md#dca-v1-exact-period)
defines what the profile scenario proves and points to the focused suites that
own its detailed rules. Run all profile scenarios with
`corepack pnpm@10.23.0 --dir js/v1 run test:reference:profiles`.
