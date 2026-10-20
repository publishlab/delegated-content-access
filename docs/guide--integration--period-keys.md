# Integrating the period-key profile

Status: Informative Draft

**Profile path:** [DCA v1 baseline
(`dca-profile-baseline`)](spec--profiles.md#3-dca-profile-baseline-profile) →
[`dca-profile-period-keys`](spec--profiles.md#5-dca-profile-period-keys-profile). See
[how profiles compose](spec--profiles.md#11-composition-rules).
The reference browser scenario below embeds the delivery in a page, so it
also runs `dca-profile-html-carrier`.

This guide is the shortest practical route through the period-key profile: a
publisher wraps item keys for a period, an issuer grants an authorized
`periodKey[t]`, and a client retains that key so later matching content can
open without another issuer call.

The [period-key guide](guide--period-keys.md) explains the model. The
[period-key specification](spec-profile--period-keys.md) and the specifications it
references remain authoritative.

## The result to preserve

A complete period-key integration has this observable path:

1. The publisher assigns groups to each item selected for period-key access,
   then creates a fresh `contentKey` and wraps it under the applicable period
   keys for those groups.
2. The page carries the item ciphertext, those item-key wraps, and the same
   period keys sealed to each issuer that may grant them.
3. The client asks an issuer only for content it cannot already open and
   relays the selected sealed period keys.
4. The issuer verifies the publisher material, applies its own authentication
   and policy, and returns only the authorized period keys.
5. The client admits and retains the returned key, opens the first item, and
   can open another item with the same publisher, `accessGroup`, generation,
   and `t` without another unlock. The
   [generation rules](spec-profile--period-keys.md#51-period-key-family-generation-and-window-identity)
   keep reused coordinates in one key lineage.

The reference scenario
[`scenario.test.js`](../js/test-reference/demo-browser/scenario.test.js) rigs that complete
reuse story: article A triggers one unlock whose response includes period keys,
then article B opens with the retained overlap key while the issuer-call count
remains one. In that scenario article A itself receives its content key from
the issuer through the independently authored item content-key alternative;
`period-label-grants.test.js` separately exercises initial and later opening through
a period-key grant.

For a period-only item in the JavaScript composition, provide a publisher
`periodKeySupply` with a plan, set client `relayPeriodKeys: true`, and supply
issuer `periodKeyInput: true`. These are independent role selections under the
optional period-key profile; an item-key route can be used without
selecting them.

## A genuine period-only composition

Period keys are optional for a baseline item-key deployment. Selecting them
requires compatible support in all three roles; the selections below are
independent trusted configuration, not fields a reader can enable in a request.

| Role | Ordinary item-key setup | Period-key selection |
| --- | --- | --- |
| Publisher | No `periodKeySupply`; supply item keys explicitly | Supply `derive(accessGroup, t)`, author item `accessGroups`, and select issuer groups in `issuerSupplyPlanFor` |
| Issuer | `periodKeyInput` defaults to `false` | Set it to `true`; policy independently grants explicit group/period labels |
| Client | `relayPeriodKeys` defaults to `false` | Set it to `true`; retain keys in a publisher-scoped `PeriodKeyCache` |

This example uses independent random period keys, without a chain construction,
family generation or chain extension. Run it from the `js/` directory. The host
provides `publisherConfig` with its signing keys, origin, randomness and issuer
public-key configuration, the matching trusted `registration`, `issuerName`, and
an already authenticated `principal`. These are host inputs, never values
accepted from the unsigned unlock request. The fixed instant and subscriber
check make this a bounded example, not a production identity or storage service.

```js
import { createPublisher } from "./integration-publisher/createPublisher.js";
import { writeJsonDelivery } from "./adapter-publisher/writeJsonDelivery.js";
import { createIssuerCore } from "./integration-issuer/createIssuerCore.js";
import { createDeliveryClient } from "./integration-client/createDeliveryClient.js";
import { JsonDeliveryReader } from "./adapter-client/JsonDeliveryReader.js";
import { PeriodKeyCache } from "./adapter-client/PeriodKeyCache.js";

// Retain this service across publishes; sample each coordinate only once.
const held = new Map();
const periodKeySupply = {
  derive(group, t) {
    const coordinate = JSON.stringify([group, t]);
    if (!held.has(coordinate)) {
      held.set(coordinate, crypto.getRandomValues(new Uint8Array(16)));
    }
    return new Uint8Array(held.get(coordinate));
  },
};
const publisher = createPublisher({
  ...publisherConfig,
  clock: { now: () => new Date("2025-10-23T14:20:00Z") },
  period: { length: 60, slots: 1 },
  periodKeySupply,
  issuerSupplyPlanFor: () => ({
    contentKeyNames: [],
    suppliedAccessGroups: ["premium"],
  }),
});
const { endpoint } = createIssuerCore({
  operatingIssuerNames: [issuerName],
  periodKeyInput: true,
  accessPolicy: {
    decide(claims, _requested, input) {
      const allowed = input.principal?.subject === "reader-123"
        && input.publisher.origin === publisherConfig.origin
        && claims.resource.data.section === "news";
      return {
        contentNames: [],
        periodGrants: allowed
          ? [{ accessGroup: "premium", periods: ["251023T1400"] }]
          : [],
      };
    },
  },
});
const render = await publisher.publish({
  resourceId: "article-A",
  data: { section: "news" },
  items: [{
    name: "bodytext", value: "Saved article", contentType: "text/plain",
    accessGroups: ["premium"],
  }],
});
const cache = new PeriodKeyCache({ namespace: "reader-123" });
const client = createDeliveryClient({
  reader: new JsonDeliveryReader(writeJsonDelivery(render), {
    publisherOrigin: publisherConfig.origin,
  }),
  issuerName,
  unlockUrl: "https://issuer.example/unlock",
  relayPeriodKeys: true,
  cache,
  transport: {
    async post(_url, request) {
      const result = await endpoint.handleDocument(
        JSON.stringify(request), registration, { principal },
      );
      return { ...result.response, contentType: "application/json" };
    },
  },
});
const opened = await client.open("bodytext");
console.log(new TextDecoder().decode(opened.bytes));
```

The publisher authors only a period-key acquisition route for this item: issuer
supply and the successful response contain `periodKeys`, with no chain keys or
item-key grant. This ordinary derive-only supply emits no `periodGeometry`.
To read another render in the same period without another unlock, pass the
same cache to that render's client; do not create a fresh cache for every page.
Different periods need their own authorized keys. The in-memory publisher Map
and client cache do not survive restart. A deployment provides atomic durable
key creation/lookup scoped to publisher and generation, retaining the same key
for a coordinate within that generation; its storage and retention policy are
host responsibilities. Independently running publisher replicas must share that
key service. Reader-context switching uses a distinct namespace and the client's
awaited reset lifecycle; eviction does not revoke delivered capability.

The modeled transport above directly invokes the document endpoint. An actual
browser deployment also supplies HTTPS, trusted Origin observation, registration
lookup and reader admission through
[`createBrowserIssuer`](../js/integration-issuer/createBrowserIssuer.js); the
in-process call does not establish those HTTP/browser properties.

## Modelling access for a publisher

Start with the items readers should be able to open with a reusable key. An
access group names a set of protected content, not a class of readers. The
publisher assigns each item selected for period-key access to its intended
groups before sealing;
the issuer separately decides which readers may receive those groups' keys.
Cached keys make that order consequential: once an item key is wrapped under
a group key, a reader who retained the matching key can open that item without
asking the issuer again.

### Start with one premium group

A publisher can begin with a single group named `premium`. If every protected
article belongs to that group, assignment can be constant. If only some do, an
existing premium flag can select the protected items to assign. This needs no
general rules engine or new article catalogue. `premium` is an example name,
not a mandatory baseline group, and period keys are an optional profile.

The authoring input could be an enum, a metadata field, a rule over existing
article metadata, or an explicit array of group names. An issuer or customer
can administer this mapping. The publisher still applies and validates it
before sealing, rather than expecting the issuer to classify already sealed
items at unlock time. No particular classification language or configuration
framework is required. Use more groups when the content classifications are
reliable and their reusable reach is useful to the business.

For a premium protected item, the publisher creates its fresh `contentKey`
and wraps it under the applicable `premium` period keys. It supplies the
matching capabilities to the issuers entrusted to grant them. The issuer can
grant a subscriber period keys, or an authorized chain-key reach when that
additional profile is selected, only when the subscriber's entitlement permits
the entire corresponding group and period reach. A chain-key supply still
leads to period-key wraps on the item.

After the first grant, another matching premium item can open from the retained
key without another unlock. That avoids an issuer round trip and its latency;
the reader still fetches the article or ciphertext and the host still opens
and presents the item. Matching requires the same publisher, family generation
and applicable group and period key, not just the label `premium`.

### Serve occasional readers from the same sealed item

An occasional reader may acquire one article through a purchase, a meter or
another online decision. A permission for that article alone does not justify
a premium period key: that key could open other matching premium items. The
issuer can instead return the item `contentKey` when the publisher has supplied
an item content-key alternative for it.

The same sealed item can serve both audiences. The publisher explicitly
authors both its premium period-key wraps and a sealed item content key for an
issuer allowed to grant individual access. A subscriber obtains reusable
premium capability; an occasional reader obtains the item's key for that
render. Both yield the same item `contentKey` and open the same ciphertext.
Separate subscriber and occasional-reader copies are unnecessary. A period-key
wrap alone does not supply an item-key issuer path; the publisher must author
that path independently if the business needs it.

Item-only delivery is also valid: an item can omit access-group assignments
and period-key wraps and rely on its complete item-key route. Neither wraps nor
a configured `periodKeySupply` promise a group-key acquisition route from this
render. [Core Section 9](spec--core-protocol.md#9-delegation-completeness) and
[period-key Section 6.1](spec-profile--period-keys.md#61-assigning-access-groups-before-sealing)
state the completeness duties. A useful publisher diagnostic names the item and
the missing route, rather than reporting a generic encryption failure.
Completeness says a route exists, not that every reader will be approved.

### Keep assignment, supply and reader grants separate

Configured groups are the groups available to the publisher; they are not all
automatically assigned to every item. Assignment determines which retained
capabilities can open the sealed bytes. Issuer supply bounds which capabilities
that issuer can grant. Reader policy chooses grants within that supply. A
later denial cannot repair an overbroad publisher assignment.

The client can find group selectors in
`contentData[contentName].keys[accessGroup]`. No extra descriptive wire field is
needed, and an ordinary unlock request does not automatically carry all of
`contentData`. Client hints are unsigned candidate requests, not authority.
Neither a copied `contentData` object nor an envelope's valid group BIND proves
article membership.

When a reader grant depends on an article's group membership, the issuer
establishes that relationship using verified `resourceJWT` metadata, trusted
configuration or issuer-held information, together with its reader policy.
A trusted policy that entitles a subscriber to the entire premium group and
applicable period reach can grant that capability independently of the current
article; it need not reconstruct article membership on every request. These
are distinct policy cases under
[core authentication and policy](spec--core-protocol.md#62-authentication-and-policy).

### Check the A/B/C reach before publishing

Consider three article body items in one publisher namespace, generation and
period. `slot-1` and `slot-2` are content-group names chosen for this example.
Each row is a separate delivery. The document-rooted reference client reads
one `dca-data` carrier per document; it does not treat several article renders
in one document as independent page roots.

| Article item | Assigned groups | Holder of matching `slot-1` key | Holder of matching `slot-2` key |
| --- | --- | --- | --- |
| A/bodytext | `slot-1` | Opens | Cannot open with that key |
| B/bodytext | `slot-2` | Cannot open with that key | Opens |
| C/bodytext | `slot-1`, `slot-2` | Opens | Opens |

A, B and C have fresh, different item content keys. C's one content key is
wrapped separately under the applicable period key for each assigned group.
Either matching group key opens C: multi-group assignment expresses OR, not
AND. The publisher includes every group intended as an alternative, with
usable period-key entries for that group. The period candidates within each
group are also alternatives; current-and-next overlap is an authoring choice,
not a required count.

If B is mistakenly wrapped under `slot-1` as well, a reader who retained that
key can open B even if an issuer later denies a B unlock. Changing the mapping
corrects newly sealed renders. It does not revoke saved keys, old ciphertext
or plaintext, and invalidating a CDN copy does not erase a reader's saved copy.
An assignment can be syntactically valid and still grant more real reach than
the business intended; review the resulting item wraps as well as the mapping.

### Choose cache and observation trade-offs deliberately

Subscribers may be paying for fewer interruptions and possibly fewer issuer
observations. Cached reuse reduces unlock calls, so a meter that counts only
unlocks cannot count every article opened with retained group capability.
If a new item or render needs its own online decision, use an independently
authored item-key route and grant that narrower key rather than a reusable
group capability.

An item key is still reusable for the same saved render. It does not enforce a
payment, observation or authorization check on every page view or load. Host
cache policy and fresh renders can increase issuer contacts, but neither can
revoke delivered keys or bytes. Article fetching, analytics and host behavior
can still reveal reading activity even when there is no unlock call. DCA does
not promise anonymous reading or guaranteed per-view tracking; the business
chooses the appropriate reuse and observation trade-off.

The normative assignment and completeness requirements are in
[period-key Section 6.1](spec-profile--period-keys.md#61-assigning-access-groups-before-sealing)
and [core Section 9](spec--core-protocol.md#9-delegation-completeness).

## Reference code to start from

- **Client:** use
  [`copy-manifest--client.json`](../js/copy-manifest--client.json) at a
  pinned repository revision. It is the supported source-copy boundary.
  [`createBrowserClient.js`](../js/integration-client/createBrowserClient.js)
  composes the client core, page reader, cache, request builder, response
  admission, and content opener. Keep the selected directories together so
  their relative imports continue to resolve. That entry reads the delivery
  from page markup, so a deployment using it also selects
  [`dca-profile-html-carrier`](spec--profiles.md#9-dca-profile-html-carrier-profile). A
  client that receives the baseline JSON document reads it with
  [`JsonDeliveryReader.js`](../js/adapter-client/JsonDeliveryReader.js)
  and composes the same pieces through
  [`createDeliveryClient.js`](../js/integration-client/createDeliveryClient.js),
  passing the reader and host-owned issuer route configuration.
- **Publisher:** copy
  [`copy-manifest--publisher.json`](../js/copy-manifest--publisher.json) at
  a pinned revision. [`createPublisher.js`](../js/integration-publisher/createPublisher.js)
  takes the host's origin, signing keys, issuers, entropy, clock and supply
  decisions. Its `publish({resourceId, data, items})` returns one render's
  `{dcaData, sealedContent}`. A host passes that render separately to
  [`writeJsonDelivery.js`](../js/adapter-publisher/writeJsonDelivery.js)
  for the baseline JSON document, or to
  [`writeMarkupDelivery.js`](../js/adapter-publisher/writeMarkupDelivery.js)
  when it embeds the delivery in a page under `dca-profile-html-carrier`.
- **Issuer:** copy
  [`copy-manifest--issuer.json`](../js/copy-manifest--issuer.json) at a
  pinned revision. [`createIssuerCore.js`](../js/integration-issuer/createIssuerCore.js)
  takes the host's required `operatingIssuerNames` and `accessPolicy` and, for period-capability
  processing, an explicit `periodKeyInput`, returning
  `{engine, processor, endpoint}`. The host supplies the publisher
  registration, authenticated reader, observed HTTP facts and opening keys
  per request. The manifest includes [`adapter-issuer/`](../js/adapter-issuer/)
  for hosts using the reference HTTP binding; the entry itself does not perform
  HTTP admission.

The demonstration
[`Publisher`](../js/demo/actors/Publisher.js),
[`Browser`](../js/demo/actors/Browser.js), and
[`IssuerServer`](../js/demo/actors/IssuerServer.js) show how the pieces are
rigged with keys, policy, storage, and transport. They are examples, not
deployment APIs. Do not copy demo or test code into a role artifact.

## Pass assignments as per-render item records

The publisher host computes assignments before calling
[`createPublisher.js`](../js/integration-publisher/createPublisher.js).
It can use a private catalogue, existing fields, a ruleset or constant groups.
These assignment inputs need not be fields in `data`, which is separately
signed as resource metadata. Sealer consumes the assigned items; it does not
run a classifier or require the classification inputs to appear in the JWT.

For example, assume `publisher` is the result of `createPublisher` with the
host's signing and issuer configuration and period-key sources for `premium`
and `archive`. In a checked JavaScript file at the copied publisher artifact's
root, the input is a plain record annotated with the entry's actual type:

```js
// Private host input: this is not resource JWT metadata.
const assignmentData = { paidEdition: true, sidebarCollection: "archive" };
const bodyGroups = assignmentData.paidEdition ? ["premium"] : ["archive"];
const sidebarGroups = [assignmentData.sidebarCollection];

/** @type {import('./integration-publisher/createPublisher.js').PublishInput} */
const input = {
  resourceId: "article-42",
  data: { section: "features" },
  items: [
    {
      name: "bodytext",
      value: "<p>The main article.</p>",
      contentType: "text/html",
      accessGroups: bodyGroups,
    },
    {
      name: "sidebar",
      value: "<p>From the archive.</p>",
      contentType: "text/html",
      accessGroups: sidebarGroups,
    },
  ],
};

const { dcaData, sealedContent } = await publisher.publish(input);
```

Here `bodytext` is assigned to `premium` and `sidebar` to `archive` within the
same render. Group names belong to the publisher namespace across all its
issuers: an issuer does not get its own classification of the shared item.
The configured `issuerSupplyPlanFor(issuer, render)` independently selects
`contentKeyNames` and `suppliedAccessGroups` for each issuer from the render's
item names and group union. Supplying an issuer with `premium` capability does
not add a premium wrap to the sidebar. Supplying only item content keys is
also possible even when item wraps allow opening with previously held group
keys; those wraps do not promise new group-key acquisition from this render.

The checked types in
[`createPublisher.js`](../js/integration-publisher/createPublisher.js)
describe the input; the publishing boundary refuses malformed or unsupported
declared fields before it produces a sealed render.

In the JavaScript reference, a publisher configured without `periodKeySupply`
can omit `accessGroups` or use an empty list for item-only publication; it
still supplies a complete item-key issuer route. A publisher configured with
`periodKeySupply` requires an explicit `accessGroups` list on every item.
That list may be empty when the item has a complete item-key issuer route.
The reference accepts grouped and ungrouped items in one render; selection
of period-key supply does not remove the item-key alternative.
A grouped item can still use an item-key-only issuer delivery while a matching
previously held group key can open its wrap.

Each call captures its render metadata, content bytes and assignment arrays
before asynchronous sealing and uses a fresh Sealer. Later changes to the
host's records do not rewrite the captured render, and concurrent calls do
not share an item's assignment or bytes. Pass the next article's input to the
next `publish` call; no mutable publisher setters are needed.

A PHP port can express the same input with native typed classes or validated
arrays, and another language can use its ordinary data types. Preserve the
field meanings, validation and per-render snapshot behavior rather than
imitating a JavaScript container. This is portable reference API guidance.

## Operations by role

These lists are the implementation path, not a second specification. Each
operation links directly to its normative owner.

### Publisher

1. Assign the item to its intended access groups before sealing under the
   [assignment requirements](spec-profile--period-keys.md#61-assigning-access-groups-before-sealing).
   Generate a fresh 16-octet item `contentKey`, encrypt the item with
   AES-128-GCM using twelve zero nonce octets and content AAD built from
   `renderId` and `contentName`, omitting item `nonce` and `aad`, under
   [the protected-item transcript](spec--content-protection.md#3-base-protected-item-transcript).
2. Obtain the 16-octet `periodKey[t]`, then wrap the item key under it
   using the
   [period-key wrapping transcript](spec--content-protection.md#4-base-period-key-content-key-wrapping).
3. Build BIND from the render and period-key coordinate, then seal the period
   key to each issuer using its provisioned public key. The
   [envelope model](spec--sealed-key-envelopes.md#2-envelope-model),
   [BIND](spec--sealed-key-envelopes.md#3-bind), and the selected
   [ECDH P-256](spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope) or
   [RSA-OAEP](spec--sealed-key-envelopes.md#5-rsa-oaep-envelope) algorithm
   define that operation.
4. Place the item record, wraps, issuer envelopes and key identifier
   in [the delivery object](spec--data-format.md#4-the-dca-data-object).
   Keep the issuer endpoint in trusted host route configuration; it is not a
   delivery member.

### Issuer

1. Admit HTTPS JSON and, when selected, browser Origin/CORS in the order
   required by the
   [endpoint binding](spec--http-binding.md#3-dca-https-json) and
   [browser profile](spec-profile--browser-origin.md#2-browser-origin-requirements).
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
   reference policy callback and its period-key trade-off.
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
   [direct transport mode](spec--response-binding.md#5-direct-representation)
   returns base64url key bytes; client-bound transport mode adds its method's
   duties.

### Client

1. Read one admitted delivery, find what retained capability already opens,
   and build a request only for unresolved items under
   [the core request rules](spec--core-protocol.md#5-core-unlock-request).
   Include a client offer only when its optional response method is selected,
   as described by [optional offers](spec--core-protocol.md#52-optional-offers)
   and [response selection](spec--response-binding.md#4-selection-and-agreement).
2. POST the request to the authenticated endpoint without automatically
   following a redirect under the
   [endpoint and channel rules](spec--http-binding.md#31-endpoint-and-channel).
   Retain the exact request association until response admission completes
   under [the request rules](spec--http-binding.md#33-request).
3. Admit only coordinates associated with that request and enforce the
   selected response representation under
   [the common response rules](spec--response-binding.md#3-inputs-and-common-response-form),
   [replay](spec--response-binding.md#11-security-considerations),
   and [failures](spec--response-binding.md#10-failures).
4. Retain admitted period keys under the
   [base period-key requirements](spec-profile--period-keys.md#base-period-key-requirements).
   Try matching cached wraps and unwrap the item `contentKey` under
   [content-key resolution](spec--content-protection.md#52-resolving-a-content-key)
   and [cached wrap attempts](spec--content-protection.md#53-cached-wrap-attempts).
5. Authenticate and decrypt the item before releasing plaintext, then reverse
   selected content encodings under
   [content opening and containment](spec--content-protection.md#54-content-opening-and-containment).

## Implementing the client store

[`PeriodKeyCache.js`](../js/adapter-client/PeriodKeyCache.js) is the
reference period-key store. Its public methods and `CacheStorage` type define
the implementation seam. The browser entry lets
[`composeClient.js`](../js/integration-client/composeClient.js) construct it
from `storage`, `cacheNamespace`, and `cacheKeyBy`, or pass a complete `cache`
of their own. The
[JavaScript reference README](../js/README.md#publisher-client-and-issuer-artifacts)
explains how those options reach the browser entry.

The store behavior has five parts:

1. Response admission supplies period keys to the resolver. The resolver
   files admitted candidates by publisher, family, and byte-identical `t`; an
   item lookup asks only for candidates at its authored coordinate.
2. `cacheNamespace` isolates logical clients that share one storage backend.
   The publisher remains part of every stored family. A deployment may add an
   issuer partition with `cacheKeyBy`, but that changes lookup eligibility,
   not the cryptographic reach of key bytes already delivered.
3. With no storage adapter, the reference cache is in memory. Its persistent
   adapter contract is asynchronous `get`, `set`, `keys`, and `remove` over
   strings. That adapter stores raw period-key bytes; a client-bound
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

A period key remains cryptographically usable after its labeled
interval. The
[normative retention rules](spec-profile--period-keys.md#base-period-key-requirements)
make later retention and time-based eviction host policy, and the
[period-key guide](guide--period-keys.md#reach-retention-and-revocation)
explains why eviction causes an ordinary miss rather than revocation. The
reference cache has no time expiry unless a host constructs it with both a
clock and an eviction callback. `createBrowserClient()` deliberately does not
accept a clock; a host needing that policy passes its own configured cache.

## Cryptography at a glance

The [overview](guide---overview.md#publisher-to-issuer-envelopes-and-bind)
explains the algorithms and widths; the owning specifications are linked from
each operation above.

## The JSON path

The [worked data-format example](design--data-format--example.md#dca-data-json)
shows all of these members with readable placeholders.

- `contentData[contentName].keys[accessGroup][]` carries candidate item-key
  wraps. Each candidate names `t`; its `nonce` and `key` wrap that item's
  `contentKey` under the `periodKey[t]`.
- `issuerData[issuerName].sealed.periodKeys[accessGroup][t]` carries the same
  period key sealed for that issuer.
- `issuerData[issuerName].sealed.contentKeys[contentName]` is the independent
  baseline item content-key alternative: through it the issuer can return that
  item's content key. Its presence does not select or disable the
  period-key-wrap alternative.
- A successful period-key result places granted period keys under
  `keys.periodKeys[accessGroup][t]`. The client associates the response with
  its request before retaining or using any returned key.

Keys and ciphertexts remain base64url strings on the wire. Do not infer
authority from object names, array order, the client clock, or mere member
presence; use the validation and binding rules in the normative documents.

## What period-key-only code does not process

A period-key-only implementation does not need chain-key behavior. Unless
the chain-key profile is separately selected, it treats these extension
members as unknown and gives them no meaning:

- the `chainsPerDay` part of top-level `periodGeometry`;
- `sealed.chainKeys` in publisher delivery or a request; and
- `keys.chainKeys` in an issuer result.

Unknown members follow the common JSON rule in
[the data-format specification](spec--data-format.md#2-common-json-rules).
Ignoring a chain member does not mean ignoring the surrounding object,
resource limits, or a selected `periodKeys` member. The item content-key
alternative in `sealed.contentKeys` is also not a chain key: it remains a
baseline alternative when authored and selected.

The [chain-key role requirements](spec-profile--chain-keys.md#chain-key-role-requirements)
assign the additional roles and paths selected for chain-key processing. The
[chain-key guide](guide--chain-keys.md) explains that model, and the
[reference extension README](../js/extensions/chain-keys/README.md)
maps it to the separate chain cache and extension tests. Period keys returned
on a chain-capable route still enter the ordinary period-key store.

## Supplying period keys at the publisher

A random publisher source must retain one independent 16-octet key per
coordinate across every render node and restart while that coordinate is
used. Generating a fresh key for each render would leave previously wrapped
items unusable with later grants. A publisher may instead use the canonical
chain-key construction privately to regenerate the same period keys. That
choice is opaque to a
period-key-only issuer and client and does not select the chain-key profile.

Omit wire `periodGeometry` for period-only authoring and configure the shared
`period.length` in minutes at the reference publisher, whether its keys are
random or privately derived.
Emit a complete geometry pair for selected chain processing, including retained
chain opening without fresh chain supply. Emit `chainKeys` only for a
separately selected chain route whose affected roles
implement its duties. Every ordinary wrap and sealed period key keeps its
explicit label, including an intended next-period alternative; the client
does not infer a label from `issuedAt` or connector `renderPeriod`.

## Opened bytes and page presentation

The client core stops at authenticated, decoded `Uint8Array` bytes.
`ContentRepresentationOpener.open(...)` returns those bytes, and the item's
`contentType` tells the host how the publisher described them. Under the
[content-handling boundary](spec--content-protection.md#7-deferred-ciphertext-and-content-handling),
the content tag does not bind `contentType`; an altered admitted spelling
can change how the host handles the same opened bytes. It remains handling
metadata rather than proof of the plaintext's type. Neither value
selects a DOM target or grants permission to execute code.

The carrier-independent `createDeliveryClient()` entry accepts a
`JsonDeliveryReader` or another reader with the same contract.
`createBrowserClient()` supplies the HTML reader. Both capture one delivery and
provide `open(contentName)`: it resolves retained capability, requests a missing
key from the configured issuer when needed, and returns
`{ contentName, contentType, bytes }`. `openLocal(contentName)` uses only capability
already held. The host retains responsibility for cache isolation, logical
context lifetime and whether an asynchronous result may still be presented.

After constructing either client, the complete item handoff is:

```js
const content = await client.open("bodytext");
await renderOpenedContent(content);
```

For a configured multi-issuer walk, call `unlockRoutes(contentNames, routes)`
before `openLocal`; the [reference README](../js/README.md) describes its
route options, and
[unlock routing and fallback](guide--unlock-fallback.md#when-the-client-may-advance)
explains which outcomes qualify.

The [article placement guide](guide--browser-content-presentation.md)
describes owner-selected handlers and separately selected map reconstruction. The `renderOpenedContent` call above is a local
application placeholder; for example, a presenter may accept
`presenter.placeContent({ [content.contentName]: content })`.

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

From the repository root, run the current period-key simulation and print
its compact, boundary-focused flow plus a decoded JWT inspection view:

```sh
node --input-type=module -e 'const { run } = await import("./js/demo/browser/scenario.js"); const { flow, inspection } = await run(); console.log(JSON.stringify({ flow, inspection }, null, 2))'
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
node --input-type=module -e 'const { run } = await import("./js/demo/browser/scenario.js"); console.log(JSON.stringify(await run(), null, 2))'
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
[`verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-admission/seal-ecdh.json`](../verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-admission/seal-ecdh.json).
Its input contains the publisher signing private/public JWKs, issuer opening
private/public JWKs, period keys, plaintext inputs, clock and deterministic
sealing material. Its expected section contains `dcaData`, sealed content,
bindings, content keys, period keys and opened plaintext. These secrets are
published test fixtures and must never be used in production.

Run the focused evidence tests from the repository root:

```sh
node --test js/test-profiles/dca-profile-period-keys.test.js
node --test js/test-reference/demo-browser/scenario.test.js
node --test js/test-reference/core-issuer/period-label-grants.test.js
node --test js/test-reference/core-client/dca-request-builder.test.js
node --test js/test-reference/adapter-client/periodkeys.test.js
node --test js/test-reference/adapter-client/cache-eviction.test.js
node --test js/test-reference/adapter-client/storage-concurrency.test.js
```

- `dca-profile-period-keys.test.js` is the complete reference profile scenario. It
  supplies the issuer no item content key, selects period-key relay and issuer
  input independently, opens one item through the issuer, and opens the next
  from retained capability without another issuer call.
- `scenario.test.js` proves cross-render reuse: one response retains the
  overlap key that opens the next render without another issuer call.
- `period-label-grants.test.js` shows explicit period-coordinate grants, the
  client opening with delivered keys and later content opening from retained
  capability.
- `dca-request-builder.test.js` exposes the request JSON and checks the exact
  maps copied from publisher delivery.
- `periodkeys.test.js` owns period-key store admission, lookup, duplicate and
  rival handling, persistence order, local bounds, and the no-second-unlock
  reuse path.
- `cache-eviction.test.js` moves across periods and family generations. It
  shows what remains readable before and after capacity eviction, including
  the issuer call caused by an ordinary miss.
- `storage-concurrency.test.js` owns the asynchronous adapter contract,
  same-family races, explicit reconciliation, capacity, optional clock policy,
  and logical-client namespace isolation.

These are JavaScript implementation tests, not independent conformance proof.
The [profile-test index](../js/test-profiles/README.md#dca-profile-period-keys)
defines what the profile scenario proves and points to the focused suites that
own its detailed rules. Run all profile scenarios with
`corepack pnpm@10.23.0 --dir js run test:reference:profiles`.
