# Content groups profile: content-name seeds, period keys and connectors

Status: Proposal
Target: optional profile and its seed source, item connector and cross-role carrier;
[chain keys](spec-profile--chain-keys.md), [period keys](spec-profile--period-keys.md),
[data format](spec--data-format.md), [profiles](spec--profiles.md),
[sealed envelopes](spec--sealed-key-envelopes.md), [content protection](spec--content-protection.md),
[response binding](spec--response-binding.md)

## Purpose and selected design

A **content group** is a named reusable protection coordinate, such as `sports`.
The publisher assigns groups to content items; issuer policy determines which
group capabilities a reader receives. A group name alone grants no entitlement.
Content-name seeds, chain keys, period keys and connectors implement this
capability.

The [content-groups diagram](guide--key-flow--diagrams.md#content-groups)
follows issuer seed opening, group-key grants and client connector opening.

Give publishers many flat named content groups without requiring subscription
rules or a catalogue-wide tree. The publisher chooses each item's groups; the
issuer decides which group capabilities a reader receives. Names such as
`sports`, `sports:football`, `premium` and `standard` are ordinary flat names.
A prefix has no cryptographic containment. An explicit `all` or combo group is
an ordinary additional group only where the publisher authors it.

- A `content-name seed` is 32 bytes for one publisher, content name, geometry
  and window. The publisher seals it to each issuer it entrusts with that
  content name. It derives the group chain roots of that content name only; no
  group catalogue is sent.
- A `chain root key` begins at the last period of that window. Stock backward
  chain derivation yields 16-byte group chain keys and 16-byte period keys.
- A `content connector` is 16 bytes. An item-specific pad derived from a group
  period key, XORed with its connector, recovers the item's random 16-byte
  content key (`ckey`).
- Each rendered content item has its own fresh ckey. Shared chain material is
  outside item records; each item carries only its applicable connectors.
- The publisher generates a fresh 16-byte `renderId` for each encryption render.
  A fresh render ID and item name isolate pads. Reusing one pad for different
  ckeys exposes their XOR.
- An issuer authorizes an item before deriving a candidate ckey from its
  relayed connector. The client accepts content only after body authentication;
  the issuer does not verify that this candidate equals the published ckey.

The content name is both the item slot and the seed coordinate. A `bodytext`
seed derives `bodytext` keys across every article of its window and never
`headline` keys, so a publisher can entrust each content name to a different
issuer. Renaming a content item changes its coordinate. There is no scope alias,
no parent seed that spans withheld content names and no per-render seed.

Shorter connectors were considered and rejected: reducing to ten bytes saves
approximately eight encoded characters per connector but reduces item-secret
strength to 80 bits and adds another ckey derivation. This proposal fixes 16.

## Status, selection and compatibility

Proposed optional profile: `dca-profile-content-groups`. Its dependency
closure is the baseline plus this profile's seed, connector and carrier duties.
It uses the stock Root/Step/Leaf construction; that reuse does not select all
issuer or client duties of the stock period-key or chain-key profiles. Those
profiles remain separately selected when their ordinary routes are composed.

Nothing is newly mandatory for a baseline-only deployment. A selecting publisher
implements seed supply and connectors; a selecting issuer implements seed
opening, whole-prefix authorization and authorized item-key recovery; and a
selecting client implements the `contentGroupKeys` response and connector opening. The ordinary setup uses two
12-hour windows and hourly periods. Top-level `periodGeometry` is shared with
ordinary period and chain routes in the same delivery. It carries the exact pair
`periodMinutes` and `chainsPerDay` when this profile is selected; no group or
family override exists. The number of windows
per day MUST divide 1,440, and the period length MUST divide a window exactly;
the stock construction's position bound still applies. There is no rounding.
For example, five windows per day and 12-minute periods fit; five windows and
60-minute periods do not. Publication settings are trusted composition, not a
profile negotiation inferred from an unsigned field.

Items may use connectors, ordinary item-key/period-key routes, or both for the
same fresh content key. An ordinary-only item may omit `connectors`. A connector-only item omits ordinary
`keys`; a present ordinary `keys` collection follows the data format and is non-empty.
Empty `keys: []` is not a completeness marker. Every protected item MUST have
at least one complete issuer-mediated route: an applicable connector whose
content name has a seed for the render window at some issuer, or an
independently complete ordinary route. An item with neither route is refused at
publication. A seedless issuer block may serve ordinary items; not every
configured issuer must receive seeds, and no rule forces every issuer to
receive every content name.

A connector-only item requires matching profile support at its client and
issuer. An article purchase, metering decision or pass beginning inside a
window may authorize less than a group's whole backward reach. Such a reader
receives the item's content key through the item route below, or through an
authored ordinary alternative; the issuer MUST NOT turn item permission into a
group-prefix grant. A publication may deliberately serve only readers whose
entitlements permit its connector routes. That limited deployment does not
guarantee access to clients without this profile.

The publisher bears the bytes of authored alternatives and seed provisioning;
the issuer bears seed custody per entrusted content name,
independent authorization and bounded opening/derivation work; the client bears
HKDF/XOR and scoped retention. Cached capabilities remain usable within their
reach. Neither a period rollover nor later refusal revokes previously delivered
keys, and omitting a later seed envelope revokes nothing. Adoption and the
selection of browser or endpoint profiles remain separate from this document.

## Delivery

The example values in this document come from the
[independent production vectors](../js/extensions/content-groups/test/fixtures/production.vectors.json),
which [the profile test](../js/test-profiles/dca-profile-content-groups.test.js)
replays. Origin `https://news.example` renders at `2026-10-14T15:05:00.000Z`
with geometry 2/60, so the render period is `261014T1500` in window
`261014T1200`. The vector file holds the full seed envelopes, token and bodies;
placeholders below state decoded widths.

Each item carries a `connectors` collection of `{group, connector}` records
for only its applicable content groups. No root group dictionary or positional
ordering is needed.
The issuer authorizes requested names from verified claims or issuer-held
state; connector names grant nothing.

```json
{
  "version": "1",
  "resourceJWT": "<signed resource claims>",
  "periodGeometry": { "chainsPerDay": 2, "periodMinutes": 60 },
  "renderPeriod": "261014T1500",
  "contentData": [
    {
      "contentName": "bodytext",
      "contentType": "text/plain",
      "connectors": [
        { "group": "politics", "connector": "cJzy9BAORNe7WOicm5bW9w" },
        { "group": "sports", "connector": "Okl5vn3NeLvXrOKNPvavtg" }
      ]
    },
    {
      "contentName": "headline",
      "contentType": "text/plain",
      "connectors": [{ "group": "politics", "connector": "OAYiZWTBOh4vZlYIeZfCaA" }]
    },
    {
      "contentName": "shoppingAd",
      "contentType": "text/plain",
      "connectors": [{ "group": "shopping", "connector": "MOKIZiqdUlGNzqTXNMXhaA" }]
    }
  ],
  "issuerData": [
    {
      "issuerName": "issuerA",
      "keyId": "a1",
      "sealed": {
        "contentWindowSeeds": [
          { "contentName": "bodytext", "windowStart": "261014T1200", "key": "<seed envelope (113 bytes)>" },
          { "contentName": "headline", "windowStart": "261014T1200", "key": "<seed envelope (113 bytes)>" },
          { "contentName": "shoppingAd", "windowStart": "261014T1200", "key": "<seed envelope (113 bytes)>" }
        ]
      }
    }
  ]
}
```

The members this profile adds:

```text
renderPeriod = canonical period label of the render
contentData[].connectors[] = {group, connector: connector16}
issuerData[].sealed.contentWindowSeeds[] = {contentName, windowStart, key: seedEnvelope113}
```

Rules for these members:

- `connectors` is a collection of `{group, connector}` records, each with a
  canonical 16-byte connector. It holds between one and `maxGroups` raw
  records. An absent member means an ordinary-only item. An empty array, a
  value that is not an array, an element that is not a non-array object or a
  record with an invalid `group` is malformed, never read as "no route": the
  item has no connector route. A selecting client MUST NOT relay a connector
  route from any part of that malformed collection, but independently valid
  sibling items retain their routes. Producer validation remains strict. Shared
  delivery/root admission and aggregate bounds are not made item-local. Record
  order is immaterial. Several records for one group are candidate connectors
  ([data format Section 2.3](spec--data-format.md#23-collections-of-named-records)).
- A root `contentGroups` member is the retired indexed form. A selecting client
  relays no content-group request member for a delivery that carries it.
- `contentWindowSeeds` holds `{contentName, windowStart, key}` records. Each
  `key` is one seed envelope for that issuer, content name and window. Each
  content name an issuer is entrusted with has between one and
  `maxSeedWindows` raw records at aligned window starts. Several records at one
  `(contentName, windowStart)` are candidate seeds. An issuer that receives
  seeds is registered with an `ecdh-p256` opening key. An absent or empty
  collection supplies no seed route. If the collection is not an array, or any
  element is not a non-array object with an own valid `contentName`, nonempty string
  `windowStart` and string `key`, a selecting client MUST NOT relay any seed
  from that issuer's collection. This rule also applies with explicit local
  narrowing. Independently valid ordinary routes and other issuer collections
  survive; shared delivery/root admission and aggregate bounds retain their
  scopes. Producer validation remains strict.
- An issuer block lists only the content names entrusted to it. In the vector
  `issuerA` holds all three; a deployment can seal `shoppingAd` seeds to a
  retail issuer alone, and that issuer can then derive no `bodytext` or
  `headline` key.
- Seeds derive group keys; recovering an item's random content key also requires
  its connector. No duplicate sealed `contentKeys` record is needed when a complete
  authorized connector route suffices.

`renderPeriod` is the fixed sealing/connector coordinate, not an authorship
timestamp, an expiry or the time the client reads. `issuedAt` is the render timestamp and
MUST NOT be substituted for a wrap or connector coordinate. No universal period
is added to baseline deliveries. A selecting publisher MUST emit an on-grid,
canonical `renderPeriod` and retain that coordinate for the render. A selecting
client uses it to choose the matching cached window and position even when it
opens old saved markup or its local clock is inaccurate. It MUST NOT infer or
replace that coordinate from the current clock. Ordinary item period-key
wraps retain their own explicit labels, including deliberate next-period
alternatives; `renderPeriod` does not restrict or replace them.

### Signed claims

The JWT retains the ordinary `renderId`, canonical `origin`, render-time
`issuedAt`, `resourceId` and object `data` claims. This profile adds no signed
claim. The vector's payload carries:

```json
{
  "renderId": "AAECAwQFBgcICQoLDA0ODw",
  "origin": "https://news.example",
  "issuedAt": "2026-10-14T15:05:00.000Z",
  "resourceId": "story1",
  "data": {}
}
```

The profile adds no group dictionary, item mask or seed-window list to the claims.
A client may decode the JWT's `renderId` to construct the item without gaining
a JWT-verification duty; decoded claims do not establish publisher identity.
Its trusted host supplies the publisher namespace and delivery association.
Visible `renderPeriod` and `periodGeometry` are derivation inputs, not
authenticated article facts. Publisher provenance is not required merely to
attempt body opening. Policy that depends on article classification obtains that
fact from verified claims or issuer-held state.

## Unlock request

The client copies common identity from the selected delivery and issuer block.
The vector request asks chain or period keys for `bodytext` and `headline` in
group `politics`, and the content key of `shoppingAd` through its `shopping`
connector:

```json
{
  "version": "1",
  "issuerName": "issuerA",
  "keyId": "a1",
  "resourceJWT": "<unchanged signed resource assertion>",
  "sealed": {
    "contentKeys": [],
    "contentWindowSeeds": [
      { "contentName": "bodytext", "windowStart": "261014T1200", "key": "<seed envelope (113 bytes)>" },
      { "contentName": "headline", "windowStart": "261014T1200", "key": "<seed envelope (113 bytes)>" },
      { "contentName": "shoppingAd", "windowStart": "261014T1200", "key": "<seed envelope (113 bytes)>" }
    ]
  },
  "renderPeriod": "261014T1500",
  "periodGeometry": { "chainsPerDay": 2, "periodMinutes": 60 },
  "requestedContentGroups": [
    { "contentName": "bodytext", "groups": ["politics"] },
    { "contentName": "headline", "groups": ["politics"] }
  ],
  "requestedContentKeys": [
    { "contentName": "shoppingAd", "group": "shopping", "connector": "MOKIZiqdUlGNzqTXNMXhaA" }
  ]
}
```

The request members this profile adds:

```text
request.sealed.contentWindowSeeds[] = {contentName, windowStart, key: unchanged seed envelope}
request.requestedContentGroups[] = {contentName, groups: [group, ...]}
request.requestedContentKeys[] = {contentName, group, connector}
request.requestedChainCutoffs[] = {windowStart, cutoff}      (optional)
request.renderPeriod, request.periodGeometry                 (copied from the delivery)
```

Seed, requested-group and requested-cutoff records require their named own
members and ignore unknown members under data format Section 2. Unknown members
do not affect authorization and MUST NOT be relayed by clients. The expressly
closed requested-item record below remains closed.

- The client relays seed envelopes, the connector and the signed token
  unchanged. Only one issuer's source block is relayed, and its seed windows may
  be a subset of that block. `contentData`, connectors other than a requested
  item's and item masks are not relayed.
- `requestedContentGroups` holds `{contentName, groups}` records; `groups` is
  a nonempty list of unique group names. Each name is the `group` of one of
  that item's `connectors` records. List and record order do not change
  authorization. An explicit empty list is refused; a request omits the content
  name instead. Several records for one content name request the union of
  their groups; a group named twice is requested once.
- `requestedContentKeys` holds `{contentName, group, connector}` records with
  exactly those three members and a canonical 16-byte connector. Each record is
  one item route: the group whose connector the issuer recovers the ckey
  through. Several records for one content name are alternative item routes
  and may name the same or different groups. The issuer keeps each record's
  `group` and `connector` together, tries every admitted route within its
  existing work limits and returns each distinct recovered candidate ckey. The
  routes grant only the requested item, never those groups' reusable keys.
- Every requested content name carries a seed in `contentWindowSeeds`, and
  every seeded content name is requested. A requested content key needs the
  seed of its render window.
- `requestedContentGroups` may be empty when `requestedContentKeys` asks an item.
  A request that selects no content-group route and no ordinary coordinate is
  refused.
- `requestedChainCutoffs`, when present, holds `{windowStart, cutoff}` records
  whose `windowStart` is a supplied window start and whose `cutoff` is a
  canonical label inside the same window. It selects that subset of supplied
  windows and caps the cutoff of each; an empty array selects none. Several
  records for one window start cap it at their lowest cutoff in label order;
  array order never raises a ceiling. Every record's window MUST belong to
  the union of seed windows actually supplied in this request; a window supplied
  for one requested content name is sufficient. A record outside that union is
  malformed and refuses before policy or opening, even beside a valid record.
  If absent, issuer policy chooses cutoffs
  within the supplied windows.
- `sealed.contentKeys` is an array and may be empty beside these members.
  Ordinary keys for unresolved items may coexist.
- Union and minimum are the normalization rules of these collections, not
  readings of the former object form. Every label is admitted before
  selection, and raw records and list entries count against the bounds before
  the issuer merges them.

Local narrowing that a client applies before it builds the request,
such as selecting items or seed windows, never reaches the wire and grants
nothing. By default a client asks every group of each needed, seeded item's
`connectors` and also offers an item-key route when this issuer supplies
the render-window seed. It chooses the ASCII-lexically first group name and
offers every distinct connector candidate of that group for the item alternative;
connector record order does not affect the choice. The issuer
independently authorizes item keys, reusable capabilities, both, or neither.
Offering a connector is not an entitlement or a requirement to grant that item.

Trusted local request-kind maps replace automatic item offering: explicitly
selecting groups does not automatically add item keys, and an explicit
`requestedContentKeys` map selects exactly those item alternatives. An empty
item map with default groups selects group-only requests; an empty group map
with explicit items selects item-only requests. A selected seed-window subset
without the render window offers no automatic item route. The client MUST NOT
invent a render-window seed or broaden a request to repair a missing item route.
Each candidate connector of the chosen group adds one requested item record.
The raw projected records count against `maxItems`; publisher request-budget
checks MUST use this same projection and bound. It changes no baseline
support requirement or cryptographic construction.

A client applying one local cutoff map to several issuers projects that map
onto each request's relayed seed windows. A present map with no matching window
MUST produce an empty requested-cutoff array; it MUST NOT become an absent
member that delegates cutoff selection to policy.

The issuer verifies and admits the JWT under core Section 4 in the selected
publisher registration before opening-key use. The reference verification host
port guarantees the ordinary header, signing-key and payload admission as well
as signature verification; it is not merely a signature primitive. `issuerName` and `keyId` select only an opening key belonging
to that registration. A configured single-key reference host matches both
explicitly; another host may supply a registration-scoped resolver. A mismatch
MUST NOT fall back to a different registration or another opening key. Signature
verification, selected caller binding and policy remain ordinary host duties.
Ordinary content-key coordinates are handled by explicitly composed base
issuer mechanics; seed opening does not replace that handler.

### Admission order and refusal

- The issuer counts raw request records and list entries against the bounds
  and checks their shapes before signature verification. A count over a bound refuses with
  `too_many_entries`; a malformed member refuses with `binding_failed`.
- A requested content name without a seed, or a seed for a content name the
  request does not ask, is malformed and refuses with `binding_failed` before
  verification.
- After verification it admits the request's coordinates structurally: the
  geometry is one complete supported pair, `renderPeriod` and every cutoff are
  canonical labels on that geometry's grid, each cutoff lies in its window,
  every supplied window start is aligned, and a requested content key has the
  seed of the render window. The verified claims carry no geometry or render
  period, so this step authenticates neither coordinate. Policy then runs with
  the request-derived coordinates (see "Issuer policy and grants"). Only an
  authorized grant opens a seed, and opening checks the envelope's AAD binding
  to the supplied geometry and window.
- Each failure keeps its class. A malformed or unsupported request coordinate
  refuses with `binding_failed` before policy. A trusted policy answer that is
  invalid under the request's coordinates, such as a chain cutoff outside its
  stated window, is a policy fault, `bad_policy`; the issuer does not relabel it
  as a caller fault. A seed that an authorized grant opens and that does not
  open under the supplied geometry and window refuses with `binding_failed`.
- Not every altered coordinate is recognized before opening. A relayed geometry
  with well-formed labels reaches policy, and its seed refuses when an
  authorized grant opens it. No seed AAD covers `renderPeriod`: an item
  recovery under an altered period may return a different candidate key. The
  client authenticates the body with that candidate; a chain or period grant
  does not depend on renderPeriod.
- A malformed request or a seed envelope that does not open at its coordinate
  refuses the whole issuer exchange: the issuer releases none of the keys it
  assembled, ordinary keys included. A structurally valid changed connector is
  not such a refusal; it produces a different candidate key.
- The refusal does not undo a key another exchange already delivered, and it
  does not stop an independent route to another issuer.
- A retired opening key is not such a refusal. The engine answers every seed
  opening under that key with `key_retired`. The issuer reports each authorized
  grant whose seed it attempted in `contentGroupKeys.errors` (see "Direct response
  and retention") and answers `200`, beside the base result's own per-coordinate
  `key_retired` entries.

## Issuer policy and grants

Unsigned connector names and request coordinates supply no entitlement. The
issuer's content-group policy receives the verified claims, its host context,
the issuer name, `contentGroups: {contentName: {groups, windows}}` for the
requested groups with their supplied windows, `items: [contentName, ...]`
for the requested content keys, and
`request: {periodGeometry, renderPeriod}`: the request's geometry pair and
canonical render-period label after structural admission, immutable and
labelled as request-derived. Policy interprets the requested windows, labels and
cutoffs under that geometry, and determines acceptable reach from the verified
claims and trusted host policy or configuration; a policy that needs the render
time reads the verified `issuedAt`. A policy that serves only some geometries
denies a request in another rather than answering grants computed for its own.
These coordinates are not verified claims. The seed AAD check at opening binds
the envelope to the supplied geometry and window; it does not establish
publisher authorship. Item recovery returns a candidate; client body
authentication establishes whether it opens the genuine content, not a factual
render time. The policy answers grants of three kinds. The vector policy answers:

```json
[
  {
    "kind": "chain",
    "contentName": "bodytext",
    "group": "politics",
    "windowStart": "261014T1200",
    "cutoffT": "261014T1800"
  },
  {
    "kind": "period",
    "contentName": "headline",
    "group": "politics",
    "t": "261014T1500"
  },
  { "kind": "item", "contentName": "shoppingAd" }
]
```

- A chain grant MUST lie inside the requested content name and group and a
  supplied window. The issuer returns the lower of the policy cutoff and the
  requested ceiling. The policy MUST authorize every period the chain key
  reaches, from the window start through the cutoff, including both endpoints
  and future matching articles; otherwise the issuer refuses the grant.
- A period grant MUST lie inside a requested content name and group, a supplied
  window and at or below that window's requested ceiling.
- An item grant MUST name a requested content key. For each requested item
  route, the issuer derives the period key of the route's group at the
  request's `renderPeriod` from the render-window seed, pads it with the
  verified `renderId` and the content name, XORs that route's connector, and
  returns each distinct resulting candidate key.
  The issuer MUST authorize the item independently of the connector's presence
  or value. It does not verify that this candidate equals the published ckey.
- A grant outside the request, a duplicate grant or a grant over its bound is a
  policy fault, never a wider answer.
- Several seed records for one content name and window are candidate sources.
  The issuer opens each one that an authorized grant uses, under the refusal
  rules above, and derives from each; distinct results become candidate keys at
  the grant's coordinate.
  Policy answers once per logical grant, not once per candidate, and a host
  meters that grant once.

A changed, valid-width connector can yield a wrong candidate key. That key
cannot authenticate the genuine encrypted item. The client MUST authenticate
content before accepting it; an issuer response proves neither successful
opening nor reader receipt. This profile defines no verified-recovery callback.

The content-group policy and the issuer's base policy are both trusted issuer
policy, and each authorizes its own routes. Neither denial vetoes the other's
affirmative grant: a base denial of an item key does not stop a content-group
item grant for the same content name, and a content-group denial leaves the
base result unchanged. Both grants stay within issuer-held policy, so neither
widens access beyond what a trusted port authorized. A host that needs a global
veto or shared accounting, such as one metering count across both routes,
implements it in both ports using shared trusted policy. This profile defines
no precedence between the two decisions.

When neither policy authorizes any coordinate in the exchange, core Section
6.2 governs complete denial. This profile adds no `notDelivered` family report,
so a content-group-only exchange with no authorized coordinate is refused with
HTTP `4xx`, rather than an empty `200`. An empty content-group grant list does
not veto an independently authorized base result or a no-key core result that
core Section 6.2 permits. A result carrying only authorized errors remains
`200` as specified below.

## Direct response and retention

### Reading the key records

`contentGroupKeys` separates these content-name-scoped grants from ordinary
access-group grants under `keys`. Both constructions deliver period keys and
chain keys. Inside `contentGroupKeys`, the subsection names the delivered key kind;
the fields of each record identify the key's coordinates, and `key` holds the
delivered key:

- `chainKeys`: `contentName`, e.g. `bodytext`; `group`, e.g. `politics`;
  `cutoff`, the chain cutoff, e.g. `261014T1800`.
- `periodKeys`: `contentName`, e.g. `headline`; `group`, e.g. `politics`;
  `period`, e.g. `261014T1500`.
- `contentKeys`: `contentName`, e.g. `shoppingAd`.

Thus the `chainKeys` record with `bodytext`, `politics` and `261014T1800`
identifies a chain key for the `politics` group of `bodytext`, delivered at
cutoff 18:00 UTC. The date label is a coordinate, not a separate key
identifier. A `contentKeys` record needs only the content name because it
delivers that rendered item's content key. Omit subsections and records for
which no key or error is returned, under the admission rules below. Record
order and JSON member order carry no coordinate meaning; the field names do.

The vector answer carries one key of each kind:

```json
{
    "keys": { "contentKeys": [] },
    "contentGroupKeys": {
        "chainKeys": [
            { "contentName": "bodytext", "group": "politics", "cutoff": "261014T1800", "key": "y-W5pEt7JcGJXpTV_JNbug" }
        ],
        "periodKeys": [
            { "contentName": "headline", "group": "politics", "period": "261014T1500", "key": "f5_xFO8-no-F7IpVyrkI1g" }
        ],
        "contentKeys": [{ "contentName": "shoppingAd", "key": "wMHCw8TFxsfIycrLzM3Ozw" }]
    }
}
```

```text
response.contentGroupKeys.chainKeys[] = {contentName, group, cutoff, key}
response.contentGroupKeys.periodKeys[] = {contentName, group, period, key}
response.contentGroupKeys.contentKeys[] = {contentName, key}
response.contentGroupKeys.errors.chainKeys[] = {contentName, group, cutoff, error: "key_retired"}
response.contentGroupKeys.errors.periodKeys[] = {contentName, group, period, error: "key_retired"}
response.contentGroupKeys.errors.contentKeys[] = {contentName, error: "key_retired"}
```

Each chain record names its cutoff label in `cutoff` and carries only the
delivered key value in `key`, as a period record does. The client derives its window and position
from that label and the complete geometry captured in its associated request;
no numeric position or outer key wrapper is transmitted. In direct transport
the value is the canonical base64url encoding of the 16 key bytes; client-bound
transport replaces that value with its selected method's protected key object.
The section fixes its `contentGroupChainKey` kind. An absent subsection is omitted.
The issuer MUST NOT return a seed, including through an additional response member. Unknown response members follow the applicable
extension-point admission rules; client rejection cannot undo disclosure of a
seed already sent.

`contentGroupKeys.errors` reports a scoped grant whose seed opening found the
selected opening key retired. For example, under a retired key:

```json
{
  "contentGroupKeys": {
    "errors": {
      "chainKeys": [
        { "contentName": "bodytext", "group": "politics", "cutoff": "261014T1800", "error": "key_retired" }
      ],
      "periodKeys": [
        { "contentName": "headline", "group": "politics", "period": "261014T1500", "error": "key_retired" }
      ],
      "contentKeys": [{ "contentName": "shoppingAd", "error": "key_retired" }]
    }
  }
}
```

- Its three collections mirror the key sections: each error record carries the
  coordinate fields of that kind's key records, an `error` member and no `key`.
  A chain error names the cutoff label the issuer would have served, the lower
  of the policy cutoff and the requested ceiling; a period error its period
  label; an item error its content name.
- Each record has exactly those coordinate fields and `"error": "key_retired"`,
  with no message or other member, and carries no key material. An empty
  collection is omitted, and `errors` with it. The issuer emits one error
  record per coordinate; a client that finds several for one coordinate uses
  the last whole record
  ([data format Section 2.3](spec--data-format.md#23-collections-of-named-records)).
- Only a coordinate the policy authorized and the issuer attempted carries an
  error. A denied or unrequested coordinate carries neither key nor error.
- No other error code appears here. A seed that does not open or a malformed seed
  still refuses the whole exchange. This profile adds
  no core error-coordinate spelling and no unavailable-family report.
- One coordinate carries keys or an error, never both: an item by content
  name, a period by content name, group and label, and a chain by content name,
  group and window. That chain window has one selected cutoff, which carries
  either chain keys or one chain error. Several chain-key records at the
  selected cutoff are candidate keys; records at different cutoffs in one
  window conflict. Several period-key or content-key records at one coordinate
  are likewise candidate keys.
- Error records and every raw key record, candidates included, count toward
  `maxResponseMembers`. Raw period records and period errors count toward
  `maxPeriodKeysPerContentGroup` for their content name and group. Chain
  records and chain errors count toward `maxWindowsPerGroup` by distinct window
  of their content name and group, so several candidates at one cutoff use one
  window.
- Before answering, the issuer MUST apply these output bounds to its actual
  candidate and error records. An answer over a bound refuses the whole
  exchange with `too_many_entries`, including otherwise successful base keys;
  it is not trimmed. This is a selected-profile finite output processing-limit
  refusal under core Section 8 and HTTP binding Section 3.4: HTTP 4xx, with no
  conditional fallback. This output refusal is distinct from the policy fault
  for an invalid trusted grant list and from the client's member-scoped
  response refusal.
- An answer that carries only errors is a `200` result, not a denial. Successful
  base and scoped siblings remain beside it. Retirement belongs to the
  request's selected opening key, so every seed opening of that exchange reports
  it; a sibling that succeeds does not depend on that key.

The client captures the pending exchange before sending: trusted publisher,
issuer and key selection, response association, resource assertion, geometry,
requested content names, groups, items, supplied windows and cutoff ceilings.
The request relays `renderPeriod` and the complete `periodGeometry` pair; the
issuer MUST NOT echo either in its response for this profile. Admission of
the `contentGroupKeys` member is atomic:

- The client counts raw records against `maxResponseMembers` before reading
  any record.
- Before opening any key, the client validates and captures the complete geometry
  pair from the immutable request associated with this response. A missing, malformed
  or unsupported pair refuses the member. The same captured pair governs every
  coordinate and cache partition throughout admission and retention, including
  after asynchronous opening. Response metadata and later delivery changes MUST
  NOT supply or override geometry. This applies to direct and client-bound responses.
- Every chain or period record sits inside a requested content name, group and
  supplied window, at or below its requested ceiling. The client derives each
  record's position from its label under the captured request geometry.
- `contentKeys` holds only requested items. Every key is canonical 16 bytes.
- `errors` holds only the three error collections, each record exactly its
  kind's coordinate fields and `"error": "key_retired"`. Every error sits inside the captured
  names, groups, windows and ceilings, or names a requested item, under the
  same rules as a key. No coordinate carries both a key and an error, and the
  raw count includes error records.
- Only then does any key open, under the kind its section fixes. The member
  reaches retention only when every key opened.
- An admitted error delivers no key, enters no cache and promotes nothing. The
  client reports each retirement to the application with its coordinate. Route
  fallback is unchanged: as with a base `key_retired`, retirement makes no
  conditional route eligible, and an independent route still runs.

A smaller authorized result is valid. Invalid supported carrier data MUST NOT
partly update retention for this member. Refusal of `contentGroupKeys` does not
invalidate independently admissible ordinary keys or other supported members;
it supplies no capability or route-control permission from the refused member.
Common response association, representation and selected transport checks still
apply to the entire affected result before any key is used. The pending
association is consumed once, even on refusal. No additional publisher or render ID is needed in the response; keys
remain reusable within their captured scope.

A recovered item ckey is held for that publisher, render and item, as a base
`keys.contentKeys` record is. Chain and period keys enter dedicated caches that
are not the ordinary period-key or chain-key caches. A cache partition is the
construction identifier, trusted publisher origin, `chainsPerDay`,
`periodMinutes`, content name and group. It names no issuer: seeds take no issuer
input, so two entrusted issuers derive equal keys, and a key one issuer
returned serves a page the other also covers. Never merge different partitions.
Retention is honest-client behavior, not replay resistance or revocation.

Different retained-secret bytes are bounded rival candidates within a
partition. A higher position subsumes a lower one only when deriving the lower
key proves they belong to the same chain. A higher-cutoff rival MUST NOT evict a
different-secret lower candidate solely because its cutoff is higher;
finite-capacity eviction remains local policy. Exact duplicates may be
deduplicated. Secret replacement produces rival chain bytes at the same content
name, group, geometry and window without a wire generation selector. A client
MUST try bounded matching candidates, in either arrival order, until body
authentication succeeds or its trial bound is reached. Equal or different
cutoff positions do not establish common ancestry by themselves. The client or
integration chooses finite storage capacity and eviction policy; this profile
prescribes no retention duration, and a new render period does not invalidate
older held keys. A persistent store applies the same bounds when it loads.

To open an item, the client reads its connector routes and the render
coordinate, asks its period-key cache and then its chain-key cache for keys of
each route's partition at `renderPeriod`, pads each key and XORs the connector.
Each result is a candidate, including results from several candidate keys or
connector records; body AES-GCM authentication decides which one is the ckey.
A failed body opening does not hide another admitted candidate or route.
In the vector, the T18 `bodytext` chain key derives the T15 period key
`9d24cf2fc780660e0ca66294e4b161c1`, whose pad recovers the `bodytext` ckey
`a0a1a2a3a4a5a6a7a8a9aaabacadaeaf`.

## Client-bound transport

Under client-bound transport the issuer wraps every content-group key entry
under the one response transport, bound to the key kind its section fixes
([response binding Section 6](spec--response-binding.md#6-client-bound-common-representation)):

- `contentGroupKeys.chainKeys`: `contentGroupChainKey`, opened to 16 raw bytes.
- `contentGroupKeys.periodKeys`: `contentGroupPeriodKey`, opened to 16 raw bytes.
- `contentGroupKeys.contentKeys`: `contentKey`, opened like a base content key.

The client derives from chain and period keys, so no non-extractability claim
applies to them. Direct fallback follows the response-binding rules: a
client-bound composition that does not accept direct fallback opens nothing from
a direct `contentGroupKeys` member or an unwrapped content-group key. A
transport that cannot open raw keys, such as an RSA-OAEP key pair without
`decrypt` usage, is refused at setup.

Error records under `contentGroupKeys.errors` are not key entries. The issuer sends
them unwrapped, its transport admits only the declared error collections with
fixed `key_retired` records beside the declared key sections, and the client admits
them without opening anything.

## Bounds and names

There is no protocol-wide catalogue or group-count ceiling. These are trusted
reference defaults, not grants or wire-negotiated capabilities:

- `maxItems` (64) bounds the content names of every per-exchange collection:
  the content names of issuer seed records, the raw records of requested group
  and item collections, and publication inputs.
- `maxGroups` (1,024) bounds the groups of one content name: its raw connector
  records and its raw requested group names across records.
- `maxSeedWindows` (2) bounds the raw seed records per issuer and content name.
- `maxWindowsPerGroup` (2) bounds chain windows per content name and group.
- `maxPeriodKeysPerContentGroup` (48) counts period results per content name and
  group, never across another content name.
- `maxResponseMembers` (2,048) bounds policy grants and raw response records,
  error records included.
- `maxCachedWindows` (4,096), `maxRivalsPerWindow` (4) and `maxTrialsPerItem`
  (4,096) bound client retention and opening trials.

Count raw records and list entries before merging, filtering, policy and
expensive derivation. Limits are
finite positive safe integers. Unknown limit names are refused, including the
retired `maxScopes` and `maxPeriodKeysPerGroup`. Producer and consumer
deployments must align capacities. Raising a local limit does not change the
profile or require enumerating a publisher's catalogue.

A publisher sizes each issuer's request as a client relays it when it needs
every item: the base members, the members this profile's default selection
adds (seed envelopes, `requestedContentGroups`, `renderPeriod` and
`periodGeometry`), the block's envelope selector and the configured allowance
for client-added members, such as a client public key, `requestedContentKeys`
or `requestedChainCutoffs`. A delivery whose request exceeds the issuer's
trusted body or entry limits is refused at publication.

The publisher also checks the response a promised route needs, as
[core Section 9](spec--core-protocol.md#9-delegation-completeness) requires.
An issuer holding a connector item's render-window seed promises one key that
opens the item: a chain of one group from that window, that group's period key
at `renderPeriod`, or the item key. Those alternatives are mutually exclusive,
so the item counts its largest one, one member. The promised items of one
exchange are delivered together, so their counts add, and the sum must fit
`maxResponseMembers`. Every group and window a request may ask is a choice,
not a promise, and does not count: 64 items with 33 groups each publish under
the default 2,048 members, and a policy granting one group per item opens all 64. A policy answer over a bound stays a policy fault; it is neither trimmed
nor continued in another exchange.

Stock chain-profile bounds remain unchanged. This dedicated carrier does not
claim to be a stock 16-member chain response. Names use the stock letter-led
ASCII grammar, at most 64 characters. Refuse noncanonical binary strings and
raw-width errors. Shared geometry, ordinary routes and unsupported fields keep
their owning profiles' rules. Protocol fields are own JSON members, and identity
values are plain strings: a name such as `toString` or `constructor` is a name
like any other, also when an implementation files records in an internal lookup.

## Byte transcripts

The following rules specify the proposal, conditional on adoption.
`F(parts)` is the UTF-8 encoding of a finite array: ASCII `[` and `]`,
comma-separated elements, and no whitespace, newline or BOM. Each string is
wrapped in ASCII double quotes and its admitted ASCII bytes are written
literally, with no optional escaping. Each integer is a nonnegative safe
integer written in shortest base-10 form, with no sign, leading zero (except
`0` itself), decimal point or exponent. The string inputs below contain no
quote, backslash or control character: they are fixed labels, stock names,
canonical base64url IDs, period labels and lowercase hexadecimal namespaces.
Their array order is fixed below; objects and arbitrary application data never
enter this transcript. Language-default JSON serialization is not authority.
`HKDF` is HKDF-SHA256 and `XOR` operates on equal 16-byte strings.

Composite construction identifier: `dca-construction-content-groups`.
This literal identifies the fixed combination below in trusted selection and cache
scope; it is distinct from the optional profile ID and is not a runtime alias
for either component. Unsupported identifiers fail admission.
Seed construction identifier: `dca-construction-content-name-seeds`.
Connector construction identifier: `dca-construction-content-connectors`.

The key namespace is derived from the existing canonical signed `origin`:

```text
publisherNamespace = lowercaseHex(SHA-256(UTF8(origin)))
```

The profile validates the canonical ASCII HTTPS origin with the shared origin
validator before hashing; malformed UTF-16, non-ASCII spellings and noncanonical
URLs are rejected rather than converted to replacement characters.
Hash the exact canonical origin string specified by the HTTP binding. Do not
slugify, trim or independently normalize it in this construction. Encode each
digest octet as exactly two lowercase hexadecimal characters, producing 64 ASCII
characters. Hash the origin string's UTF-8 bytes, not a JSON-encoded string.
Different origins therefore separate site chain material even when they share a
publisher-retained secret. A change of origin changes the chain material; several
domains do not implicitly share access. Hashing avoids the collisions of ordinary
slugification, subject to SHA-256 collision resistance. There is no additional
`siteName` field on the page or in the JWT. Origin signature verification,
registration and client cache partitioning retain their existing rules.
For `https://news.example` the namespace is
`2d0a016473ff75fd2afa3cc1dac401896235215a4a61e06d11129ff3442837a7`.

For one publisher-scoped 32-byte retained secret:

```text
contentNameSeed = HKDF(
  retainedSecret,
  salt = UTF8("dca-construction-content-name-seeds"),
  info = F(["content-name-window", publisherNamespace, contentName,
            chainsPerDay, periodMinutes, windowStartLabel]),
  length = 32)
```

Window labels are canonical stock chain labels at aligned window starts.
The delivery's root `periodGeometry` MUST contain exactly `periodMinutes` and
`chainsPerDay` for chain processing. No per-group or ordinary-family geometry
override is allowed. Changing publisher, content name, retained secret or
geometry changes key material. With retained secret `00..1f`, content name
`bodytext`, geometry 2/60 and window `261014T1200`, the seed is
`d9b1274900e75c2ddcf90b8015ffc87d4bd60eb8b84298d5ec9d57e26223a8f3`.

Apply stock `rootChainKey` with `contentNameSeed` as `keyDerivationSecret`, the
exact group name, the window's terminal label and geometry. Apply stock
Step/Leaf unchanged. A seed handle refuses every derivation outside its declared
window. Root/Step/Leaf keep the stock construction identifier. The seed
derivation is new; its namespace must not be confused with independently
provisioned stock family material or mixed into a cache solely because names
and periods match.

The publisher derives an item's connectors at its `renderPeriod`, from the seed
of the item's content name and the window that contains that period, not at the
window start:

```text
itemPad = HKDF(
  groupPeriodKey,
  salt = UTF8("dca-construction-content-connectors"),
  info = F(["item-pad", renderId, contentName]),
  length = 16)

connector = randomItemCkey XOR itemPad
randomItemCkey = connector XOR itemPad
```

In the vector, the `bodytext` `politics` period key at `261014T1500` is
`9d24cf2fc780660e0ca66294e4b161c1`, its pad over
`["item-pad","AAECAwQFBgcICQoLDA0ODw","bodytext"]` is
`d03d5057b4abe27013f14237373b7858`, and the connector is
`cJzy9BAORNe7WOicm5bW9w`.

The period key input already depends on the publisher-scoped seed, content
name, group name, geometry and period through the seed and stock chain
derivations. Those coordinates do not need to be repeated in the item-pad
transcript. A fresh random `renderId` separates renders; `contentName` separates
items within one render, including items sharing the same group period key.
The fixed connector salt and `"item-pad"` label separate this derivation from
other uses of the key. Publisher origin is therefore not an item-pad input.
Reusing the same period key, render ID and item name reuses the pad and is unsafe
for distinct content keys. Signed claims and seed-envelope bindings retain their
separate origin and authorization checks; this simplification does not change
those checks or the seed derivation.

Content encryption reuses [content protection Section 3](spec--content-protection.md#3-base-protected-item-transcript):
a fresh independent uniformly random 16-byte ckey used for one encryption,
twelve zero nonce bytes, AES-128-GCM with a 16-byte tag, and the content AAD
`LP(renderId) || LP(contentName)` of
[content protection Section 3.2](spec--content-protection.md#32-content-aad).
Keep normal `sealedContent` placement and omit item `nonce` and `aad`.
This profile changes key recovery, not the base content transcript. Type,
encodings and other JWT claims are outside the content tag; their admission,
capture and handling rules still apply. Signing and issuer authorization
remain separate requirements.

Render IDs are exactly 16 random bytes represented as canonical 22-character
base64url. Item and group names follow stock grammar. Period keys and content
keys are 16 raw bytes. A period key is not used directly as the XOR pad.

## Seed envelope and issuer custody

Selected seed envelope algorithm: `ecdh-p256-content-name-seed`.
For each envelope the publisher MUST generate a fresh ephemeral P-256 keypair
and MUST NOT reuse one across envelopes, including rival seeds at the same
coordinate. The 32-byte shared x-coordinate is the AES-256-GCM key, with no
KDF. The AES-GCM nonce MUST be twelve zero bytes; it is implicit and MUST NOT
be carried. The payload is the 32-byte seed with a 16-byte tag. Layout:
65-byte uncompressed public point, then 48-byte encrypted seed/tag = 113 bytes
(151 unpadded base64url characters). The fresh keypair makes the zero nonce
safe: each agreement encrypts one seed. Reusing a pair with the same recipient
repeats the AES key and nonce, and a different AAD does not make that reuse
safe. Resending bytes already sealed is not a new encryption.

The issuer MUST refuse a decoded envelope of any other length before it opens
it. That includes the former 125-byte layout, which carried a 12-byte nonce
between point and ciphertext; there is no fallback to it. The stock 97-byte,
16-byte-payload key envelope has the same construction for its smaller
payload. Do not infer envelope algorithms from length.

Publisher and issuer update together. An issuer on this procedure refuses
deliveries sealed in the former 125-byte layout: republish them, or open them
with a separately maintained implementation of the former procedure. Clients
relay seed envelopes unchanged and never open them. The AAD, seed derivation,
chain and period keys, connectors and wire members are unchanged.

The issuer opens a seed envelope with the opening key its trusted registration
selects, under that key entry's `ecdh-p256` procedure.

Envelope AAD is:

```text
F(["dca-bind-content-name-seed", publisherNamespace, renderId,
   issuerName, contentName, windowStartLabel, chainsPerDay, periodMinutes])
```

For `origin = "https://news.example"`, render ID
`AAECAwQFBgcICQoLDA0ODw`, issuer `issuer`, content name `bodytext`, window
`261014T1200` and geometry 2/60, the exact AAD is the UTF-8 encoding of this
single line (no newline):

```text
["dca-bind-content-name-seed","2d0a016473ff75fd2afa3cc1dac401896235215a4a61e06d11129ff3442837a7","AAECAwQFBgcICQoLDA0ODw","issuer","bodytext","261014T1200",2,60]
```

The [independently computed binding vector](../js/extensions/content-groups/test/fixtures/seed-aad.json)
records the binding, UTF-8 text and hexadecimal octets for ports to check. The
[production vectors](../js/extensions/content-groups/test/fixtures/production.vectors.json)
record complete envelopes for issuer `issuerA` with their ephemeral keys,
shared secrets and AAD.

The issuer selects its opening key only from the verified publisher's trusted
registration for the selected issuer. GCM coordinate binding is not publisher
authorship: the resource JWT is verified separately before policy or opening.
Never return the seed to a client. Clear temporary seed bytes when practical;
retention is trusted issuer configuration, not a client request choice. An
issuer that retains an opened seed MUST associate reuse with the exact envelope
bytes it opened and the same opening context: verifying registration, issuer,
opening-key selection, envelope algorithm and bound derivation scope. A digest
may identify the exact bytes. Publisher/content name/window alone is
insufficient: a caller can seal unrelated bytes with the public opening key.
Retention MUST NOT bypass current admission or authorization. This rule adds no
signed digest or publisher-authorship promise to a seed envelope. The reference
issuer retains no seed between exchanges. When an exchange ends, answered or
refused, content-groups zeroes its opened seed bytes and each seed handle's owned
buffer, then releases its exchange-local handles. A chain port may make further
copies; their cleanup belongs to that port's lifecycle. The composed stock port
releases its generation with the exchange, but does not explicitly overwrite its
internal copy. These JavaScript cleanup steps do not guarantee erasure of every
runtime or cryptographic-library copy.

A seed entrusts the issuer with every group of its content name in its
publisher, geometry and window namespace. Verified publisher claims or
issuer-held policy govern compliant issuer decisions, but cannot
cryptographically limit a seed holder to those groups. A seed reaches no other
content name. Use a narrower item-key route, or seal a content name to no issuer
that is not trusted that broadly. A holder keeps its reach after a later article
omits its seed block; omission is not revocation.

## Cross-role behavior

Publisher: snapshot caller data and bytes before the first suspension, generate
fresh render IDs and ckeys, derive each connector item's connectors at
`renderPeriod`, seal each listed content-name seed to its issuer, sign the
resource, then
encrypt content. One seed serves every item of its content name in its window.
The render timestamp records rendering, independently of the chosen connector
period. Do not accept preauthored key wraps for a newly generated item key.
Ordinary item envelopes for the same fresh ckey come from the publisher's base
issuer supply; an ordinary-only item requires a complete ordinary issuer route.

Issuer: enforce raw structural limits before verification, verify the JWT and
registration, admit requested coordinates and consult trusted policy before
opening seeds. Authorize each granted chain's entire prefix before opening any
seed. Refuse a chain grant when full reach is not authorized; no article-only key
projection from a seed is promised. Authorize an item before recovering its
candidate key. Seed custody is broader than compliant policy, and policy must
not infer entitlement from presence or derivability.

Client: admit the pending response fully before retention; derive only backward
within the matching window. Try each matching connector and accept recovered
content only after body AES-GCM authentication succeeds. Failed alternatives do
not block valid siblings. A cached chain may open later matching renders of the
same content name without an issuer call. An ordinary-only item opens through
the composed base resolver. No new request expands the reach of keys already
held. Reader reset retires this client's held keys and stored material; it
cannot revoke keys a reader copied elsewhere.

Authorized reader sharing and pooling remain accepted as in the security model.
Known ckeys expose pads for that render/item and allow same-context connector/
body substitution, without revealing period keys. An authorized item request
with a zero connector returns that item's pad as its candidate key. This pad
is limited to its render and content name; it is not a period key and does not
supply pads for another render or item. A changed connector may make the issuer
return a wrong candidate; genuine body authentication still fails with that key.
This mechanism claims no standalone publisher authorship. Context reuse with
different ckeys is forbidden. Negative tests supplement the stated construction
assumptions; finite tests are not a general security proof.

## Evidence and implementation acceptance

The [reference extension](../js/extensions/content-groups/README.md)
implements this document through the reference publisher, issuer and delivery
client, with both client-bound methods. Its evidence:

- [The profile test](../js/test-profiles/dca-profile-content-groups.test.js)
  replays vectors written from `node:crypto` without implementation code: the
  issuer opens the fixed seed envelopes and answers the fixed request with the
  fixed response, and the composed client builds that request and opens a
  chain-key, a period-key and an item-key item.
- The extension's own tests cover construction, request and response admission,
  bounds, policy faults, wrong-candidate body refusal and cache partitions.
- The cross-extension composition tests run the roles over JSON and HTML
  carriers with direct and client-bound transport, shared storage, reload, reset,
  substitutions and denials checked by real decryption attempts.

An unpublished flat prototype and a later private experiment informed the
design; their shapes, literals and sizes are not this proposal's. This evidence
does not establish a general security proof or support for an untested
transport.

Before adoption, settle the profile duties and deployment support, validate any
selected browser and endpoint profiles, and reconcile the profile catalogue,
portable reference API, conformance evidence and implementer release notes.
