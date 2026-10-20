# Integrating issuer-side metering

Status: Informative Draft

This guide shows where an issuer integrating the JavaScript reference makes
and records a metered access decision. Metering is issuer application
behavior, not a DCA wire profile: DCA supplies authenticated resource facts,
presented key coordinates, and a seam where the issuer's policy decides what
to grant.

The worked request below uses the
[`dca-profile-period-keys`](spec--profiles.md#5-dca-profile-period-keys-profile)
profile because period keys make the visibility trade-off concrete. The policy and key-result accounting
seams are not period-key mechanisms.

The central limit is simple: an issuer can observe an unlock and prepare a
key-bearing response for return. It cannot prove that the client received or
used that response, and it cannot observe a later opening performed with a key
the client already holds. The
[capability lifecycle](spec-profile--period-keys.md#11-capability-lifecycle) and
[pre-delivery and revocation rules](spec-profile--period-keys.md#121-pre-delivery-and-revocation)
own that limit. Grant item content keys when every unresolved render must
reach the issuer. Use period-key grants when fewer issuer calls and
bounded reuse are the intended trade-off.

## What arrives from the client

An unlock request has this shape. The sealed values are publisher-produced
ciphertexts relayed by the client; their presence grants nothing.

```json
{
  "version": "1",
  "issuerName": "meter",
  "resourceJWT": "<publisher-signed resource>",
  "keyId": "2026-09",
  "sealed": {
    "contentKeys": {
      "bodytext": "<content key sealed for this issuer>"
    },
    "periodKeys": {
      "subscriber": {
        "260921T1000": "<period key sealed for this issuer>"
      }
    }
  }
}
```

The client may omit sealed coordinates it does not need or support. It may also
present more publisher-authored alternatives than the issuer will use. The
issuer therefore never treats the request as entitlement or as trusted profile
selection.

After structural admission and publisher-signature verification, the
reference reduces the request to the coordinates the policy may decide on:

```js
const requested = {
  contentNames: ["bodytext"],
  accessGroups: ["subscriber"],
  periodCoordinates: { subscriber: ["260921T1000"] },
};
```

The policy does not receive the unsigned request object. Its other inputs are:

- `claims.resource`: the verified `resourceJWT` payload, including
  publisher-signed `origin`, `resourceId`, `renderId`, `issuedAt`, and `data`;
- `input.principal`: the identity and entitlements authenticated by the
  issuer host;
- `input.context`: an issuer-owned snapshot such as prior metered renders,
  account state, or the captured request time; and
- `input.publisher.origin`: the verified signed publisher origin filled by
  the engine, rather than a value supplied by the client.

Publisher-signed `data` is authenticated publisher context. It is not the
reader's identity and does not grant access by itself; issuer configuration
decides which of its fields have policy meaning.

The [core request specification](spec--core-protocol.md#5-core-unlock-request)
defines the wire object. The policy contract is visible in
[`IssuerEngine.js`](../js/core-issuer/IssuerEngine.js), and the reference
request construction is exercised in
[`dca-request-builder.test.js`](../js/test-reference/core-client/dca-request-builder.test.js).

## Inject the access-policy callback

Supply an object with `decide(claims, requested, input)` to
`createIssuerCore`. The callback returns only coordinates the issuer intends to
grant, plus optional opaque host work to commit after the key result is
prepared:

```js
const accessPolicy = {
  async decide(claims, requested, input) {
    const { renderId, resourceId, data } = claims.resource;
    const { principal, context, publisher } = input;

    if (typeof principal?.user !== "string") {
      return { contentNames: [], periodGrants: [], policyData: [] };
    }

    const mayRead = await decideFromIssuerState({
      principal,
      context,
      publisherOrigin: publisher.origin,
      resourceId,
      publisherData: data,
    });

    if (!mayRead || !requested.contentNames.includes("bodytext")) {
      return { contentNames: [], periodGrants: [], policyData: [] };
    }

    return {
      contentNames: ["bodytext"],
      periodGrants: [],
      policyData: [{ type: "view", user: principal.user, renderId }],
    };
  },
};

const { engine, processor, endpoint } = createIssuerCore({
  operatingIssuerNames: ["meter"],
  accessPolicy,
  periodKeyInput: true,
});
```

`contentNames` grants item content keys. Each `periodGrants` entry names an
`accessGroup` and explicit `periods` from `requested.periodCoordinates`. The
engine clamps both answers to presented coordinates, but that clamp is not
authorization: the callback must also check that each selected period falls
within the entitlement and meter rules in issuer-owned state.

When the decision depends on an entitlement, meter or policy-state source that
times out, is unavailable, refuses to answer or returns unusable input, the
issuer has no policy decision. The policy throws a typed
`policy_unavailable` error, which the endpoint answers with 503 and no key
material; an empty decision such as `{}` is a completed denial. It does not
substitute a default grant. The normative rule is in
[authentication and policy](spec--core-protocol.md#62-authentication-and-policy).

The example returns no `periodGrants` deliberately. Granting the
`subscriber` family would let the client open later matching articles from its
cache, so those views would never call this meter. To meter reusable access
instead of individual renders, the corresponding decision is:

```js
return {
  contentNames: [],
  periodGrants: [
    {
      accessGroup: "subscriber",
      periods: (requested.periodCoordinates.subscriber ?? []).filter((t) =>
        entitlementCoversPeriod(t, principal, context),
      ),
    },
  ],
  policyData: [{ type: "capability-grant", user: principal.user, renderId }],
};
```

`entitlementCoversPeriod` is an issuer-owned check over the requested label
and the subscriber's validity window. It must not infer entitlement from the
unsigned label alone. That `policyData` shape is illustrative; the host
defines and validates its own pending records. The demo `IssuerBusinessData`
accepts only its `view`
record, so a `capability-grant` record needs a deployment-owned applier. The
event being counted is the reusable grant, not each later article it can open.

The demonstration policy in
[`AccessPolicy.js`](../js/demo/support/AccessPolicy.js) shows a complete
callback with public, entitlement, and metered rules. It is example policy,
not a deployment API or a required business model.

## Commit only for a deliverable key result

Do not debit a meter merely because `decide` returned a grant. Envelope
opening, response representation, or final transport preparation can still
fail. Returning `policyData` lets the policy describe a pending host action
without mutating durable state inside the decision.

The issuer integration should:

1. authenticate the caller and take one issuer-owned policy snapshot;
2. call the engine with that `principal` and `context`;
3. prepare the selected
   [response representation](spec--response-binding.md#4-selection-and-agreement)
   and the binding's [HTTP response](spec--http-binding.md#34-response);
4. determine whether the prepared response contains at least one key member;
   and
5. atomically apply the returned `policyData` only when that key-bearing
   response is ready to return.

This commit point means "the issuer issued a key-bearing response," not "the
reader received, opened, or viewed the content." A network failure after the
commit remains possible. A product that charges money needs its own retry,
reservation, settlement, and reconciliation rules around that boundary.

The demo [`IssuerServer`](../js/demo/actors/IssuerServer.js) performs this
ordering, while
[`IssuerBusinessData`](../js/demo/actors/issuer/IssuerBusinessData.js)
validates and applies its pending view records. A production integration must
replace the in-memory store with its own atomic, idempotent operation. A
stable event identity such as publisher plus reader plus signed `renderId`
prevents a retry from consuming the same render twice.

The JavaScript reference provides
[`createIssuerCore`](../js/integration-issuer/createIssuerCore.js) and an
[issuer copy manifest](../js/copy-manifest--issuer.json). Use the supported
entry to compose the issuer engine, processor and endpoint. Authentication,
policy snapshots, durable storage and atomic metering commits remain the host's
responsibility. The demo illustrates that commit ordering; its in-memory store
is not a production accounting backend.

## Share one snapshot across optional routes

A mixed issuer can have an ordinary `accessPolicy` and the content-groups
contribution's `policy`. Their affirmative grants are independent alternatives:
a denial in one port does not veto the other. For a global account suspension
or one article meter, take one host snapshot after caller authentication and
publisher verification, and make both ports consult it. Do not fetch entitlement
state twice or debit from either decision callback.

Here `snapshot.permitsItem`, `grantsWithin` and `permitsPeriod` are the host's
pure decisions over that captured state, not reference APIs. `grantsWithin`
selects only presented content-group coordinates; `permitsPeriod` authorizes
every period reached by a reusable grant. A request coordinate is not authority.

```js
const accessPolicy = {
  decide(claims, requested, { context: snapshot }) {
    return {
      contentNames: snapshot.refused
        ? []
        : requested.contentNames.filter((name) =>
            snapshot.permitsItem(claims.resource, name),
          ),
      // Describe the one pending event even if only the other route grants.
      policyData: snapshot.pendingEvent,
    };
  },
};
const groupPolicy = {
  decide(input) {
    const snapshot = input.context;
    return {
      grants: snapshot.refused ? [] : snapshot.grantsWithin(input),
      authorizePeriod: (contentName, group, t, windowStart) =>
        !snapshot.refused &&
        snapshot.permitsPeriod(contentName, group, t, windowStart),
    };
  },
};
```

Compose `accessPolicy` through `createIssuerCore` and `groupPolicy` through the
existing `contentGroupsProfile.issuerContribution({ chain, policy: groupPolicy })`.
The [extension recipe](../js/extensions/content-groups/README.md#base-seams-it-uses)
owns that optional composition. Pass the same `{ principal, context: snapshot }`
to `endpoint.handleDocument(document, registration, policyInput, capturedAtMs)`.
Principal and context are opaque host values: the engine preserves their
identities rather than making JSON copies of a transaction, Map or class instance.
The host keeps the snapshot stable throughout the attempt.

The base policy's `policyData` is the pending event for the whole exchange;
the content-group policy does not return a second accounting channel. Thus an
ordinary refusal with connector-only success can still commit that event. A
refusal from both policies produces no key-bearing response and commits none.
Use the signed publisher/render and authenticated reader to identify one event,
independent of how many grant routes or keys the final response contains.

After endpoint success, prepare transport with `KeyDelivery` configured with
`composedSections: core.responseSections` and finish the HTTP response before committing.
Count both ordinary and selected extension keys in that **final** body:

```js
// Imports from js/core-shared--client-issuer/responseKeys.js:
// deliveredKeys, composedKeys, settleComposedSections.
const sections = settleComposedSections(core.responseSections);
const hasKey =
  !deliveredKeys(finalBody.keys).next().done ||
  !composedKeys(finalBody, sections).next().done;
if (hasKey) await store.applyOnce(eventId, answered.policyData);
// Only now return the already prepared response.
```

`store`, `eventId`, the snapshot, transport preparation and HTTP construction
belong to the host. `applyOnce` denotes its atomic idempotent storage operation,
not a reference helper. Do not count only `keys`, which misses a connector-only
answer, or count pending policy intent before preparation succeeds. Refuse the
whole response if preparation or accounting fails. A late source failure or
transport-preparation failure commits nothing. A successful mixed answer and a
successful connector-only answer each count once. This records issuance, not
proof of plaintext use; a wrong connector candidate or a later network loss
cannot establish that the reader viewed the article.

## Choose what the meter means

- **Per unresolved render:** grant only `contentNames`, so the issuer returns
  item content keys. A later render without a retained usable key reaches the
  issuer again.
- **Per reusable capability grant:** grant `periodGrants` and count the grant.
  Later matching opens are intentionally invisible to the issuer.
- **Per request:** usually the wrong event. Refusals, retries, cache hits, and
  responses that deliver no key make request count differ from access.
- **Per plaintext view:** unavailable to an issuer once the client holds a
  usable key. DCA does not provide remote observation of client rendering.

An issuer response cache can also bypass a fresh policy decision. Do not place
a metered route behind such a cache unless its cache key, replay semantics,
and accounting operation deliberately implement the same meter. Multiple or
fallback issuers similarly need shared accounting state, or an explicit rule
that each issuer maintains a separate meter.

## Run and inspect the reference evidence

Run from `js/`:

```sh
node --test test/access-policy.test.js
node --test test-reference/demo-browser/scenario.test.js
```

[`access-policy.test.js`](../js/test/access-policy.test.js) demonstrates two
metered reads that each receive the item's content key from the issuer, followed
by denial, retry-safe counting by signed `renderId`, no debit when no key is
delivered, and the key limitation: a second article opened from a retained
period key never reaches the issuer. `scenario.test.js` makes that retained-key
behavior visible as two opened articles and one issuer call.

These tests exercise the reference integration. They do not make its example
metering policy part of the DCA protocol.
