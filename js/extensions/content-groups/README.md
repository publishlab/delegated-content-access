# Content groups extension

Status: proposal code. It implements `dca-profile-content-groups` from the
[content groups proposal](../../../docs/spec-profile--content-groups.md) through the reference publisher, issuer and
delivery client. It is not an adopted profile or a conformance claim.

A publisher seals one 32-byte seed per content name and window to each issuer it lists. The issuer derives group
chain keys and period keys from that seed, or recovers one item's content key, and answers only what its policy
grants. The client files the keys in two dedicated caches and opens items through its plain `open()`.

## How a key reaches the reader

An example with geometry 2/60 (two windows a day, hourly periods), origin `https://news.example` and one issuer
`issuerA`:

- The publisher gets `issuerSeedWindows: {issuerA: {bodytext: ["261014T1200"]}}` and renders at 12:20. The item
  `bodytext` carries the item option `contentGroups: ["politics", "sports"]`. The render period is `261014T1200`.
- For each group the publisher derives the seed of (origin, `bodytext`, 2/60, window `261014T1200`), runs stock
  Root/Step/Leaf to the group's period key at T12, derives a 16-byte pad from that key, the render ID and
  `bodytext`, and writes `connector = contentKey XOR pad` to `contentData.bodytext.connectors.politics`.
- The publisher seals the seed to `issuerA` under
  `issuerData.issuerA.sealed.contentWindowSeeds.bodytext.261014T1200`.
- The client sends `requestedContentGroups: {bodytext: ["politics", "sports"]}` with the unchanged seed envelope.
  The issuer verifies the JWT, asks its policy, opens the seed and answers
  `contentGroups.chainKeys.bodytext.politics.261014T1800 = key`.
- The client files that chain key under (construction, origin, 2/60, `bodytext`, `politics`). A later `bodytext`
  article rendered at T15 in the same window opens without a request. A `headline` item or a T19 render does not.
- An item route asks one content key: the client names `requestedContentKeys: {shoppingAd: "sports"}` locally, the
  request carries `{group: "sports", connector}`, and the issuer authorizes the item, derives a candidate key
  and answers `contentGroups.contentKeys.shoppingAd`. The client authenticates the body with that candidate.
  A changed valid-width connector can yield a wrong key; the issuer does not verify correct recovery.

The wire members:

```text
issuerData.<issuer>.sealed.contentWindowSeeds.<contentName>.<windowStart> = seedEnvelope
contentData.<contentName>.connectors.<group> = connector16
request.requestedContentGroups.<contentName> = [group, ...]
request.requestedContentKeys.<contentName> = {group, connector}
response.contentGroups.chainKeys.<contentName>.<group>.<cutoffLabel> = key
response.contentGroups.periodKeys.<contentName>.<group>.<periodLabel> = key
response.contentGroups.contentKeys.<contentName> = key
response.contentGroups.errors.chainKeys.<contentName>.<group>.<cutoffLabel> = {"error": "key_retired"}
response.contentGroups.errors.periodKeys.<contentName>.<group>.<periodLabel> = {"error": "key_retired"}
response.contentGroups.errors.contentKeys.<contentName> = {"error": "key_retired"}
```

Chain values carry no numeric position or outer key wrapper. The cutoff label and captured request geometry
supply position; direct values are base64url and client-bound values are the method's protected key object.
The section still fixes `contentGroupChainKey`, and caches retain the derived position and complete identity.

The delivery also carries root `renderPeriod` and `periodGeometry`; the request relays both with an optional
`requestedChainCutoffs`. Responses echo neither; the client uses the complete pair captured from its
immutable associated request for admission and retention, even across asynchronous key opening. A root `contentGroups` member is the retired indexed form, and the extension refuses it.

The issuer writes `contentGroups.errors` when a seed opening finds the selected opening key retired. Each
coordinate the policy granted and the issuer attempted with that seed gets the fixed leaf at the depth of its key
map. The answer stays 200, and base coordinates report their own `key_retired` entries under root `errors`. The
client admits the errors together with the keys of the same member, files no key for an error, and reports each in
the application's `errors` as
`{section, contentName, group, windowStart?, t?, error: "key_retired", consumer: "contentGroups"}`.

## Known content keys and connector isolation

Opening an item lets the reader recover every pad for that item by XORing its
content key with each public connector. Those pads belong to that render and
content name; they are not the other groups' period keys or chain keys. See the
profile's [cross-role behavior](../../../docs/spec-profile--content-groups.md#cross-role-behavior).

The production-role tests in
[`production-roles.test.js`](test/production-roles.test.js) make this
case explicit:

- **"standard access reveals the item's premium pad but cannot open premium-only
  items"** obtains only the standard chain, opens an item accessible through
  either standard or premium, and recovers its premium pad. Reusing that pad or content key fails on
  premium-only articles in the same period, a later period and the next window.
  Genuine premium keys open those targets as positive controls.
- **"a zero-connector item grant exposes only that item's pad, not another name
  or render"** checks that an exposed pad cannot open another content name or a
  fresh render in the same period.
- **"deliberately reused item-pad context exposes the XOR of two different
  content keys"** demonstrates why a fresh render ID is required when publishing
  different keys for the same content name.

Run these checks from `js/`:

```sh
node --test --test-name-pattern='standard access reveals|a zero-connector item grant|deliberately reused item-pad context' extensions/content-groups/test/production-roles.test.js
```

These tests exercise concrete opening attempts. HKDF's resistance to recovering
period keys from exposed pads is a cryptographic assumption, not something a
finite test suite proves.

## Composition: `contentGroupsProfile`

`referenceProfile.js` exports one frozen object, `contentGroupsProfile`. It holds no state; each member is the
extension's own role entry.

- `profile`, `construction`: `dca-profile-content-groups` and `dca-construction-content-groups`.
- `publisherContribution(options)`: the second argument of `createPublisher(base, contribution)`. Options are
  `retainedSecret` (32 bytes), `periodGeometry`, optional `limits`, `issuerSeedWindows`
  (`{issuerName: {contentName: [windowStart, ...]}}`). Stock chain derivation is
  supplied by this extension's required `chain-keys` dependency; an explicit
  `chain` override remains available for instrumentation/substitution. An issuer listed there needs the
  base algorithm `ecdh-p256`.
- `issuerContribution({chain, policy, limits})`: the contribution to `createIssuerCore(base, contribution)`. The
  optional `chain` uses the stock implementation by default. The
  policy's `decide(input)` receives `contentGroups: {contentName: {groups, windows}}`, `items` and
  `request: {periodGeometry, renderPeriod}`, and answers `{grants, authorizePeriod}`. `request` is frozen and
  request-derived: unsigned, it grants nothing. The policy reads the requested windows under that geometry, takes
  reach from the verified claims and trusted configuration, takes render time from the verified `issuedAt`, and
  denies a geometry it does not serve. Grants are `{kind: "chain", contentName, group, windowStart, cutoffT}`,
  `{kind: "period", contentName, group, t}` and `{kind: "item", contentName}`. `authorizePeriod` answers `true` for
  every period a chain grant reaches. There is no verified-recovery callback: a returned candidate proves
  neither successful body opening nor reader receipt. The contribution declares the three response sections,
  so `createIssuerCore` returns them in its `responseSections`.
- `client(config)`: the client bundle. The host passes two cache factories,
  `createPeriodKeyCache` (builds `adapter-client/PeriodKeyCache.js`) and `createChainKeyCache` (builds the
  chain-keys `ChainKeyCache`), plus optional `chain`, `limits`, `narrowing`, `storage` and `namespace`.
  Stock chain geometry/coordinate/label operations are used unless overridden;
  cache factories remain explicit for host storage, clocks and lifecycle choices. The bundle's
  `composeOptions` holds `requestBuilderFactory`, `recoverySources` and `responseSections`, ready to spread into
  `createDeliveryClient` or `composeClient`. The bundle's `namespace` scopes its two caches only; the ordinary
  cache takes `cacheNamespace` through `composeClient`. A host that separates logical clients over one storage
  sets both.
- `responseSections`, `kindDescriptors`: the three response sections and the two derivation kinds,
  `contentGroupChainKey` and `contentGroupPeriodKey`, each `{width: 16, open: "raw"}`.
- `keyDeliveryMembers(composedKinds)`, `capabilityOptions(composedKinds)`: the `KeyDelivery` members and the
  `clientBoundKeyCapability` options for client-bound transport. Both refuse with `bad_config` a kind set that is
  not frozen or lacks either content-group kind.

The content-groups policy and the base `accessPolicy` are both trusted, and each authorizes its own routes. Neither
denial vetoes the other's grant: a base denial of `bodytext` does not stop a content-group `item` grant for
`bodytext`, and a content-group denial leaves the base keys. A host that needs a global veto or shared accounting,
such as one metering count, implements it in both ports over shared trusted policy.

Content groups use their own content-name-scoped chain keys. Reusing the stock chain construction does not select
the ordinary period-key or chain-key profiles, and selecting content groups does not disable them. A publication
using connector routes does not need ordinary chain-key routes for those items. Compose both only when the
publication also authors ordinary routes that need them; ordinary item-key routes can remain in either setup.

The stock issuer composition is a content-groups contribution beside ordinary item-key routes. A single issuer core
cannot combine it with the stock chain-keys injected engine: `createIssuerCore` refuses a `responseSectionSource`
beside an injected engine. One base engine serves both when the host composes the chain-keys `core-issuer` pieces
itself:

```js
createIssuerCore(
  {
    operatingIssuerNames,
    accessPolicy,
    periodCapabilitySource: requireChainRepresentation(
      chainKeyCapabilitySource({ representation }),
    ),
    selectedExtensions: ["chain-keys"],
    // only with representation "chain-keys"
    capabilityEncoders: { "chain-keys": chainKeyCapabilityEncoderFor() },
  },
  contentGroupsProfile.issuerContribution({ chain, policy }),
);
```

The host then owns two duties:

- Every unlock passes one captured instant: `endpoint.handleDocument(document, registration, policyInput,
capturedAtMs)`. The chain source reads no clock, so without the instant every unlock answers 500, with or without
  a chain grant. `createBrowserIssuer` captures the instant from its clock.
- `requireChainRepresentation` wraps the chain source. When the host admits relayed period keys
  (`periodKeyInput: true`), an independent grant for a family the request relays as period keys is a clean chain
  miss. Unwrapped, the engine refuses to answer it from the base period-key prefix, and the whole answer is a 500.
  Wrapped, that family gets no key and the other routes still answer.

The block "one base issuer engine composing chain keys with content groups" in
`../../test-extensions/content-groups-composition.test.js` covers both duties, each policy's denial, the Origin
check before policy and client-bound wrapping. The separate-issuer tests in
`../../test-extensions/content-groups-separate-issuers.test.js` cover a stock chain issuer beside a content-group
issuer in one client, held-key reuse on another render, and an independent item fallback when the stock issuer
returns 503. They use direct responses and an in-process JSON transport, not browser Origin admission or
client-bound delivery. Seeds use ordinary `ecdh-p256`; a compact-selected seed block refuses.

For the optional mixed setup, the client wraps the stock chain request builder instead of replacing it. Given a
content-group client `bundle`, pass these options alongside the stock `chainKeyProfile` and its caches:

```js
const mixedRequestOptions = {
  requestBuilderFactory: (options) =>
    bundle.requestBuilderFactory({ innerBuilder: chainKeyRequestBuilderFactory(options) }),
  recoverySources: bundle.composeOptions.recoverySources,
  responseSections: bundle.composeOptions.responseSections,
};
```

`chainKeyRequestBuilderFactory` comes from `../chain-keys/core-client/ChainKeyRequestBuilder.js`.
Spreading `bundle.composeOptions` alone selects its default base request builder, without the stock chain request
builder. The [mixed composition test](../../test-extensions/composition-boundaries.test.js) exercises the nested
builders through the HTML carrier with gzip, both kinds of chains and ordinary item keys. It uses a Node DOM
harness, not a deployed browser. This is optional composition evidence, not a recommended publication default.

The extension imports stock chain geometry/coordinate/label functions directly.
Publisher and issuer seed handling also uses chain generation from the shared
publisher/issuer slice; a client-only import does not reach that generator or
publisher supply adaptation. Explicit `chain` overrides preserve useful
instrumentation/substitution. These source dependencies do not select client-
bound transport; the host still settles the selected transport kinds:

```js
const kinds = ecdhP256.settleKindDescriptors(contentGroupsProfile.kindDescriptors);
new KeyDelivery({ random, profile: ecdhP256, ...contentGroupsProfile.keyDeliveryMembers(kinds) });
clientBoundKeyCapability(keyPair, ecdhP256, contentGroupsProfile.capabilityOptions(kinds));
```

The issuer members always carry every content-group section, so a client-bound response never carries a
content-group key unwrapped. `referenceProfile.js` imports every role; a browser build imports
`core-client/client.js` directly.

Local `narrowing` selects what the request asks. Without it, each needed content name with a seed from this
issuer asks every group of its connector map and offers one item connector, choosing the first group in ASCII
order. The item alternative is offered only when the selected seeds include the render's window. The issuer may
answer with reusable keys, an item key, both or neither; an offered connector grants nothing.

An explicit `requestedContentGroups` or `requestedContentKeys` map disables automatic item offering. Use an empty
`requestedContentKeys` map to retain the default group requests without item alternatives, or supply only
`requestedContentKeys` for item-only requests. `requestedChainCutoffs` caps the cutoff per window;
`requestedContentItems` and `seedWindows` narrow locally and never reach the wire. A malformed connector map
suppresses that item's connector routes as a unit; valid sibling items remain usable. Producer validation and
shared delivery context and aggregate limits remain strict.

## Base seams it uses

- Publisher: `createPublisher` contributions. The Sealer runs `itemPreparation` after it draws the content keys and
  before it signs; `itemOptionMembers` admits the item option `contentGroups`. `requestRelay` hands the base request
  budget the client's own projection of the delivery, so a page whose request an issuer's body limit refuses does
  not publish. `routes` refuses a render whose promised connector keys at one issuer, one per connector item with
  a render-window seed there, exceed `maxResponseMembers`.
- Issuer: `createIssuerCore` contributions. `requestBounds` reads the request with the client's request reader before
  signature verification: it counts raw members, and refuses with `binding_failed` a requested content name without
  a seed or a seed for a name the request does not ask. The
  `responseSectionSource` answers `contentGroups`, registers its seed opener under the base
  procedure `ecdh-p256`, and opens seeds through the engine's `openAuxiliary(sealed, {aad})`, so the trusted key
  entry picks the procedure. An issuer that selects another procedure opens no seed, and the exchange refuses.
- Client: `requestBuilderFactory` (`ContentGroupRequestBuilder` wraps the base request and reports `keyFamilies`
  and `routeProjection`), one `ContentKeyResolver` recovery source and one response-section consumer. The
  consumer opens keys through the resolver's `openKey` and hands a recovered item key to `holdContentKey`.
- Caches: one `PeriodKeyCache` and one `ChainKeyCache`, each with its own `entryKind` and structured `partition`.
  Neither is the client's ordinary cache. The client passes `maxResponseMembers` and `maxWindowsPerGroup` to the
  chain cache as `maxMembersPerMessage` and `maxMembersPerFamily`, because one answer carries more chain keys than
  the chain-keys bounds of 16 per answer and two per family.
- Transport: `KeyDelivery` `composedSections` and `composedKinds`, and the `composedKinds` option of
  `clientBoundKeyCapability`.

It copies no base lines.

## Custody, cache and reset

- Seeds stay at the issuer. The issuer opens a seed per exchange, derives and keeps none between exchanges. When the
  exchange ends, answered or refused, it zeroes the opened bytes and disposes every seed handle, which zeroes the
  owned buffer. The publisher disposes its connector handles the same way. Both release their local handles.
  Cleanup of additional copies belongs to the chain port; the stock port releases its generation but does not
  explicitly overwrite its internal seed copy. The tests establish owned-buffer clearing, not complete memory
  erasure. No response carries a seed.
- A cache partition names construction, trusted origin, `chainsPerDay`, `periodMinutes`, content name and group.
  It names no issuer: two entrusted issuers derive equal keys, so a key from one serves a page the other covers.
- A recovered item key is held like a base `keys.contentKeys` entry. Reader reset drops it.
- Under client-bound transport, chain and period keys open to 16 raw bytes, because the client derives from them;
  an item key opens to an AES-GCM handle like a base content key.
- `clearReaderContext()` on the delivery client reaches the recovery source, which clears both caches.
- Sibling client instances over one persistent `namespace` share its entries: a reset in one deletes them, and a
  later write or reconciliation in another can restore them. Discard sibling instances before a reader reuses
  the namespace, as the [reader-context lifecycle](../../README.md#browser-reader-context-lifecycle) requires.
- A malformed request or a seed envelope that does not open refuses the whole issuer exchange, base keys
  included. A changed valid-width connector instead produces a candidate that cannot open the genuine body. Keys an earlier route delivered stay held. In
  `unlockRoutes`, a refusal makes no conditional route eligible; a later route still runs when the host marks it
  `independent`.

## Limits

Trusted defaults from `settleLimits`; an unknown name is refused, including the retired `maxScopes` and
`maxPeriodKeysPerGroup`:

- `maxItems` 64 bounds every per-exchange content-name map.
- `maxGroups` 1024 per content name; `maxPeriodKeysPerContentGroup` 48 per (content name, group).
- `maxSeedWindows` 2 per issuer and content name; `maxWindowsPerGroup` 2 per (content name, group).
- `maxResponseMembers` 2048 over grants and raw response entries, `key_retired` errors included.
- `maxCachedWindows` 4096, `maxRivalsPerWindow` 4 and `maxTrialsPerItem` 4096 on the client.

Retention and work bounds are independent. The content-group recovery source
shares one `maxTrialsPerItem` allowance across all ordinary-period candidates
and chain routes for that item. Its trusted chain-cache port receives
`chainCandidateBudget: { remaining }` and spends it before each chain derivation,
including work whose resulting period bytes duplicate another candidate. A
raised `maxRivalsPerWindow` makes more retained rivals available, but only those
within the remaining item allowance are derived; a deliberately smaller trial
limit can leave an older retained rival unread. Pending obtaining-operation keys
use the same allowance and retain their first-use priority. Storage reload does
not reset or enlarge this work allowance. Ordinary chain-cache callers that omit
the explicit budget keep their separate four-chain default.

## Checks

From `js/`:

```sh
node --test extensions/content-groups/test/*.test.js test-extensions/content-groups*.test.js \
  test-profiles/dca-profile-content-groups.test.js
```

`npm run test:reference:extension:content-groups` runs this directory's tests alone. The cross-extension tests in
`../../test-extensions/` are described in [their README](../../test-extensions/README.md).

## Wire sizes

Historical setup: the now-retired `measure-content-groups.mjs`, captured after commitment
removal on 2026-10-16. Each row publishes one item `bodytext` at render T12,
geometry 2/60, whose connector map names N groups. The measurement selects group-only requests
with `narrowing: { requestedContentKeys: {} }`; it measures reusable delivery rather than the default
item alternative. One issuer holds seeds for
the T12 and the next window. The policy grants a T18 chain for every group,
over direct transport. Metadata excludes `sealedContent` and includes both seed
envelopes. The script authenticates the genuine body from the captured answer
before saving. Figures are compact JSON / gzip bytes in `artifacts/`:

- 1 group: metadata 1,188 / 869, request 967 / 739, response 125 / 114.
- 2 groups: metadata 1,225 / 895, request 979 / 744, response 178 / 144.
- 10 groups: metadata 1,521 / 1,065, request 1,075 / 763, response 602 / 324.
- 100 groups: metadata 4,851 / 2,899, request 2,155 / 965, response 5,372 / 2,185.

Compared with the prior captures, raw metadata is 193 bytes smaller and the
request is 110 bytes smaller in each row. Removing the response geometry echo
saves another 55 raw response bytes in each row. Removing the redundant chain
position/key wrapper saves a further 21 raw bytes per returned chain in these
T18 examples: 21, 42, 210 and 2,100 bytes respectively. Response figures were
recomputed from the retained captures with only those syntax changes; a fresh
measurement run authenticated actual bodies and reproduced their response sizes.
Gzip figures describe these captures, not fixed compression savings: signatures,
envelopes, render IDs and nonces are random.
